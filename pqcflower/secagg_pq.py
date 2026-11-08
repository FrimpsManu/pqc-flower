"""Post-quantum SecAgg+: Flower's secure aggregation with ML-KEM-768 instead of ECDH.

SecAgg+ (Bell et al., CCS 2020) hides each farm's model update from the server: every farm adds
random masks that cancel out only when all updates are summed. Flower 1.39 uses ECDH P-384 twice:
  pk2/sk2  each pair of farms derives a key to encrypt the secret shares they send each other
  pk1/sk1  each pair derives a seed for the pairwise mask they add (one +, one -)
Shor's algorithm breaks ECDH, so a quantum attacker who recorded the traffic could rebuild every
mask and see each farm's individual update.

ECDH lets two farms compute the same secret without ever talking to each other. ML-KEM cannot:
one side encapsulates and must send a ciphertext to the other. The four Flower stages stay as
they are; the ciphertexts ride along with the messages the server already forwards:

  setup         each farm makes two ML-KEM-768 key pairs and a 32-byte pair-seed master m
  share keys    for every neighbour j, farm i encapsulates to j's pk2 and encrypts its secret
                shares with that key (as Flower does with the ECDH key). If i < j, i also creates
                the pair seed s_ij = HKDF(m_i, "i|j") and sends it to j, encrypted with a second
                encapsulation to j's pk1. One payload per neighbour, forwarded by the server.
  masked input  j decapsulates both ciphertexts. Both farms now hold s_ij; masks as in Flower.
  unmask        unchanged. A farm's shared "sk1" secret is (pk1's decapsulation seed || m), so if
                farm d drops out the server can rebuild every mask that involved d: from m_d for
                pairs where d created the seed, and by decapsulating the forwarded capsule for
                pairs where the other farm did. This reveals exactly what Flower reveals when it
                rebuilds a dropped farm's ECDH sk1: the masks of the dropped farm, nothing more.

Masks: Flower's pseudo_rand_gen folds the 32-byte seed into a 32-bit integer before seeding NumPy,
so every mask is one of 2**32, few enough to try them all on a laptop. prg() below seeds NumPy's
PCG64 with the full seed instead.

Classical SecAgg+ is Flower's own code (flwr.server.workflow.SecAggPlusWorkflow / secaggplus_mod).
This module adds pq_secaggplus_mod (farm side) and MLKEMSecAggPlusWorkflow (server side). The
dispatcher and unmask_stage below are adapted from Flower 1.39 (Apache-2.0).
"""

import base64
import importlib
import os
from logging import DEBUG, ERROR, INFO
from typing import cast

import numpy as np
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import mlkem
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from flwr.app import ConfigRecord, Context, Message, RecordDict
from flwr.app.message_type import MessageType
from flwr.common import ndarray_to_bytes, ndarrays_to_parameters, parameters_to_ndarrays
from flwr.common.secure_aggregation.crypto.shamir import combine_shares, create_shares
from flwr.common.secure_aggregation.ndarrays_arithmetic import (
    factor_combine,
    factor_extract,
    get_parameters_shape,
    parameters_addition,
    parameters_mod,
    parameters_multiply,
    parameters_subtraction,
)
from flwr.common.secure_aggregation.quantization import dequantize, quantize
from flwr.common.secure_aggregation.secaggplus_constants import RECORD_KEY_CONFIGS, RECORD_KEY_STATE, Key, Stage
from flwr.common.secure_aggregation.secaggplus_utils import share_keys_plaintext_concat, share_keys_plaintext_separate
from flwr.compat.common import recorddict_compat as compat
from flwr.server.workflow.constant import MAIN_CONFIGS_RECORD, MAIN_PARAMS_RECORD
from flwr.server.workflow.constant import Key as WorkflowKey
from flwr.server.workflow.secure_aggregation.secaggplus_workflow import SecAggPlusWorkflow, WorkflowState
from flwr.supercore import log

# import_module: flwr.client.mod.secure_aggregation re-exports a *function* named secaggplus_mod.
flower_mod = importlib.import_module("flwr.client.mod.secure_aggregation.secaggplus_mod")

KEM_SEED_B = 64  # ML-KEM-768 decapsulation key, stored as its seed
MASTER_B = 32    # pair-seed master m


# --- Building blocks ------------------------------------------------------------------------------

def _kdf(secret: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=info).derive(secret)


def _fernet(shared_secret: bytes, info: bytes) -> Fernet:
    return Fernet(base64.urlsafe_b64encode(_kdf(shared_secret, info)))


def _pair_seed(master: bytes, low: int, high: int) -> bytes:
    """Pair seed created by the farm with the lower node id."""
    return _kdf(master, f"pqcflower/secagg/pair|{low}|{high}".encode())


def _pack(*parts: bytes) -> bytes:
    return b"".join(len(p).to_bytes(4, "little") + p for p in parts)


def _unpack(data: bytes) -> list[bytes]:
    parts, i = [], 0
    while i < len(data):
        n = int.from_bytes(data[i:i + 4], "little")
        parts.append(data[i + 4:i + 4 + n])
        i += 4 + n
    return parts


def _wrap_seed(src: int, dst: int, seed: bytes, recipient_pk1: bytes) -> tuple[bytes, bytes]:
    """Encrypt a pair seed to the recipient's pk1: (KEM ciphertext, wrapped seed)."""
    shared_secret, kem_ct = mlkem.MLKEM768PublicKey.from_public_bytes(recipient_pk1).encapsulate()
    plaintext = src.to_bytes(8, "little") + dst.to_bytes(8, "little") + seed
    return kem_ct, _fernet(shared_secret, b"pqcflower/secagg/pair-seed").encrypt(plaintext)


def _unwrap_seed(src: int, dst: int, kem_ct: bytes, wrapped: bytes, dk1_seed: bytes) -> bytes:
    shared_secret = mlkem.MLKEM768PrivateKey.from_seed_bytes(dk1_seed).decapsulate(kem_ct)
    plaintext = _fernet(shared_secret, b"pqcflower/secagg/pair-seed").decrypt(wrapped)
    if int.from_bytes(plaintext[:8], "little") != src or int.from_bytes(plaintext[8:16], "little") != dst:
        raise ValueError(f"pair seed capsule is not for the pair {src} -> {dst}")
    return plaintext[16:]


def prg(seed: bytes, num_range: int, dimensions_list: list[tuple[int, ...]]) -> list[np.ndarray]:
    """Mask generator seeded with the whole seed (Flower's pseudo_rand_gen keeps only 32 bits)."""
    gen = np.random.Generator(np.random.PCG64(np.random.SeedSequence(int.from_bytes(seed, "little"))))
    return [np.asarray(gen.integers(0, num_range, size=dims, dtype=np.int64)) for dims in dimensions_list]


# --- Farm side (ClientApp mod) --------------------------------------------------------------------

def _setup(state: flower_mod.SecAggPlusState, configs: ConfigRecord) -> dict:
    flower_mod._setup(state, configs)  # reads the protocol parameters (and makes ECDH keys we replace)
    dk1, dk2 = mlkem.MLKEM768PrivateKey.generate(), mlkem.MLKEM768PrivateKey.generate()
    # sk1 is what gets secret-shared for dropout recovery: pk1's decapsulation seed and the master m.
    state.sk1 = dk1.private_bytes_raw() + os.urandom(MASTER_B)
    state.pk1 = dk1.public_key().public_bytes_raw()
    state.sk2 = dk2.private_bytes_raw()
    state.pk2 = dk2.public_key().public_bytes_raw()
    return {Key.PUBLIC_KEY_1: state.pk1, Key.PUBLIC_KEY_2: state.pk2}


def _share_keys(state: flower_mod.SecAggPlusState, configs: ConfigRecord) -> dict:
    state.public_keys_dict = {int(nid): (pk1, pk2) for nid, (pk1, pk2) in configs.items()}
    if len(state.public_keys_dict) < state.threshold:
        raise ValueError("Available neighbours number smaller than threshold")
    all_pks = [pk for pair in state.public_keys_dict.values() for pk in pair]
    if len(set(all_pks)) != len(all_pks):
        raise ValueError("Some public keys are identical")
    if state.public_keys_dict[state.nid] != (state.pk1, state.pk2):
        raise ValueError("Own public keys are displayed in dict incorrectly")

    state.rd_seed = os.urandom(32)
    b_shares = create_shares(state.rd_seed, state.threshold, state.share_num)
    sk1_shares = create_shares(state.sk1, state.threshold, state.share_num)
    master = state.sk1[KEM_SEED_B:]

    dsts, payloads = [], []
    for idx, (nid, (pk1, pk2)) in enumerate(state.public_keys_dict.items()):
        if nid == state.nid:
            state.rd_seed_share_dict[state.nid] = b_shares[idx]
            state.sk1_share_dict[state.nid] = sk1_shares[idx]
            continue
        shared_secret, kem_ct2 = mlkem.MLKEM768PublicKey.from_public_bytes(pk2).encapsulate()
        shares = share_keys_plaintext_concat(state.nid, nid, b_shares[idx], sk1_shares[idx])
        encrypted_shares = _fernet(shared_secret, b"pqcflower/secagg/shares").encrypt(shares)
        kem_ct1 = wrapped = b""
        if state.nid < nid:
            kem_ct1, wrapped = _wrap_seed(state.nid, nid, _pair_seed(master, state.nid, nid), pk1)
        dsts.append(nid)
        payloads.append(_pack(kem_ct2, encrypted_shares, kem_ct1, wrapped))
    return {Key.DESTINATION_LIST: dsts, Key.CIPHERTEXT_LIST: payloads}


def _collect_masked_vectors(state, configs: ConfigRecord, num_examples: int, updated_parameters) -> dict:
    payloads = cast(list[bytes], configs[Key.CIPHERTEXT_LIST])
    srcs = cast(list[int], configs[Key.SOURCE_LIST])
    if len(payloads) + 1 < state.threshold:
        raise ValueError("Not enough available neighbour clients.")
    dk2 = mlkem.MLKEM768PrivateKey.from_seed_bytes(state.sk2)
    dk1_seed, master = state.sk1[:KEM_SEED_B], state.sk1[KEM_SEED_B:]

    pair_seeds: dict[int, bytes] = {}
    for src, payload in zip(srcs, payloads, strict=True):
        kem_ct2, encrypted_shares, kem_ct1, wrapped = _unpack(payload)
        shared_secret = dk2.decapsulate(kem_ct2)
        plaintext = _fernet(shared_secret, b"pqcflower/secagg/shares").decrypt(encrypted_shares)
        actual_src, dst, rd_seed_share, sk1_share = share_keys_plaintext_separate(plaintext)
        if actual_src != src or dst != state.nid:
            raise ValueError(f"Node {state.nid}: shares from {actual_src} to {dst} arrived as {src} -> {state.nid}")
        state.rd_seed_share_dict[src] = rd_seed_share
        state.sk1_share_dict[src] = sk1_share
        if src < state.nid:
            pair_seeds[src] = _unwrap_seed(src, state.nid, kem_ct1, wrapped, dk1_seed)
        else:
            pair_seeds[src] = _pair_seed(master, state.nid, src)

    # Quantize and weight the update exactly as Flower does.
    ratio = num_examples / state.max_weight
    q_ratio = round(ratio * state.target_range)
    parameters = parameters_multiply(parameters_to_ndarrays(updated_parameters), q_ratio / state.target_range)
    quantized = factor_combine(q_ratio, quantize(parameters, state.clipping_range, state.target_range))
    dims = [a.shape for a in quantized]

    quantized = parameters_addition(quantized, prg(state.rd_seed, state.mod_range, dims))
    for nid, seed in pair_seeds.items():
        mask = prg(seed, state.mod_range, dims)
        quantized = (parameters_addition if state.nid > nid else parameters_subtraction)(quantized, mask)
    quantized = parameters_mod(quantized, state.mod_range)
    return {Key.MASKED_PARAMETERS: [ndarray_to_bytes(a) for a in quantized]}


def pq_secaggplus_mod(msg: Message, ctxt: Context, call_next) -> Message:
    """Flower's secaggplus_mod, with the ML-KEM stages above (dispatcher adapted from Flower 1.39)."""
    if msg.metadata.message_type != MessageType.TRAIN:
        return call_next(msg, ctxt)
    if RECORD_KEY_STATE not in ctxt.state.config_records:
        ctxt.state.config_records[RECORD_KEY_STATE] = ConfigRecord({})
    state = flower_mod.SecAggPlusState(**ctxt.state.config_records[RECORD_KEY_STATE])
    configs = msg.content.config_records[RECORD_KEY_CONFIGS]
    flower_mod.check_stage(state.current_stage, configs)
    state.current_stage = cast(str, configs.pop(Key.STAGE))
    flower_mod.check_configs(state.current_stage, configs)

    out_content = RecordDict()
    if state.current_stage == Stage.SETUP:
        state.nid = msg.metadata.dst_node_id
        res = _setup(state, configs)
    elif state.current_stage == Stage.SHARE_KEYS:
        res = _share_keys(state, configs)
    elif state.current_stage == Stage.COLLECT_MASKED_VECTORS:
        out_content = call_next(msg, ctxt).content
        fitres = compat.recorddict_to_fitres(out_content, keep_input=True)
        res = _collect_masked_vectors(state, configs, fitres.num_examples, fitres.parameters)
        for arr_record in out_content.array_records.values():
            arr_record.clear()
    elif state.current_stage == Stage.UNMASK:
        res = flower_mod._unmask(state, configs)
    else:
        raise ValueError(f"Unknown SecAgg+ stage: {state.current_stage}")

    ctxt.state.config_records[RECORD_KEY_STATE] = ConfigRecord(state.to_dict())
    out_content.config_records[RECORD_KEY_CONFIGS] = ConfigRecord(res, False)
    return Message(out_content, reply_to=msg)


# --- Server side (ServerApp workflow) ------------------------------------------------------------

class MLKEMSecAggPlusWorkflow(SecAggPlusWorkflow):
    """Flower's SecAggPlusWorkflow for the ML-KEM farms above. Only dropout recovery changes."""

    def share_keys_stage(self, grid, context, state: WorkflowState) -> bool:
        ok = super().share_keys_stage(grid, context, state)
        # Keep the pair-seed capsules: Flower deletes the forwarded payloads after the next stage,
        # and they are needed to rebuild the masks of a farm that drops out.
        state.share_keys_survivors = set(state.active_node_ids)
        state.seed_capsules = {}
        for dst, payloads in state.forward_ciphertexts.items():
            for src, payload in zip(state.forward_srcs[dst], payloads, strict=True):
                _, _, kem_ct1, wrapped = _unpack(payload)
                if kem_ct1:
                    state.seed_capsules[src, dst] = (kem_ct1, wrapped)
        return ok

    def unmask_stage(self, grid, context, state: WorkflowState) -> bool:
        """Flower 1.39's unmask_stage with ML-KEM mask recovery and the full-seed PRG."""
        cfg = context.state.config_records[MAIN_CONFIGS_RECORD]
        current_round = cast(int, cfg[WorkflowKey.CURRENT_ROUND])
        active_nids = state.active_node_ids
        dead_nids = state.sampled_node_ids - active_nids

        def make(nid: int) -> Message:
            neighbours = state.nid_to_neighbours[nid]
            cfg_record = ConfigRecord({
                Key.STAGE: Stage.UNMASK,
                Key.ACTIVE_NODE_ID_LIST: list(neighbours & active_nids),
                Key.DEAD_NODE_ID_LIST: list(neighbours & dead_nids),
            })
            return Message(content=RecordDict({RECORD_KEY_CONFIGS: cfg_record}), dst_node_id=nid,
                           message_type=MessageType.TRAIN, group_id=str(current_round))

        log(DEBUG, "[Stage 3] Requesting key shares from %s clients to remove masks.", len(active_nids))
        msgs = grid.send_and_receive([make(nid) for nid in active_nids], timeout=self.timeout)
        state.active_node_ids = {msg.metadata.src_node_id for msg in msgs if not msg.has_error()}

        collected: dict[int, list[bytes]] = {nid: [] for nid in state.sampled_node_ids}
        for msg in msgs:
            if msg.has_error():
                state.failures.append(Exception(msg.error))
                continue
            res = msg.content.config_records[RECORD_KEY_CONFIGS]
            for owner, share in zip(cast(list[int], res[Key.NODE_ID_LIST]), cast(list[bytes], res[Key.SHARE_LIST]),
                                    strict=True):
                collected[owner].append(share)

        masked_vector = state.aggregate_ndarrays
        del state.aggregate_ndarrays
        dims = get_parameters_shape(masked_vector)
        for nid, share_list in collected.items():
            if len(share_list) < state.threshold:
                log(ERROR, "Not enough shares to recover secret in unmask vectors stage")
                return False
            secret = combine_shares(share_list)
            if nid in active_nids:
                masked_vector = parameters_subtraction(masked_vector, prg(secret, state.mod_range, dims))
                continue
            # Dropped farm: rebuild the pairwise masks its active neighbours added for it.
            if nid not in state.share_keys_survivors:
                continue  # dropped before sharing keys: no neighbour ever masked with it
            dk1_seed, master = secret[:KEM_SEED_B], secret[KEM_SEED_B:]
            for neighbour in (state.nid_to_neighbours[nid] & active_nids) - {nid}:
                if nid < neighbour:
                    seed = _pair_seed(master, nid, neighbour)
                else:
                    kem_ct1, wrapped = state.seed_capsules[neighbour, nid]
                    seed = _unwrap_seed(neighbour, nid, kem_ct1, wrapped, dk1_seed)
                mask = prg(seed, state.mod_range, dims)
                masked_vector = (parameters_addition if nid > neighbour else parameters_subtraction)(masked_vector, mask)

        recon = parameters_mod(masked_vector, state.mod_range)
        q_total_ratio, recon = factor_extract(recon)
        inv_dq_total_ratio = state.quantization_range / q_total_ratio
        aggregated = dequantize(recon, state.clipping_range, state.quantization_range)
        offset = -(len(active_nids) - 1) * state.clipping_range
        for vec in aggregated:
            vec += offset
            vec *= inv_dq_total_ratio

        results = state.legacy_results
        parameters = ndarrays_to_parameters(aggregated)
        for _, fitres in results:
            fitres.parameters = parameters
        log(INFO, "aggregate_fit: received %s results and %s failures", len(results), len(state.failures))
        parameters_aggregated, metrics_aggregated = context.strategy.aggregate_fit(
            current_round, results, state.failures)  # type: ignore
        if parameters_aggregated:
            context.state.array_records[MAIN_PARAMS_RECORD] = compat.parameters_to_arrayrecord(
                parameters_aggregated, True)
            context.history.add_metrics_distributed_fit(server_round=current_round, metrics=metrics_aggregated)
        return True
