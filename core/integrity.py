import json
from core.db import log_action, append_block, get_last_block_hash

def record_chain_event(db_path, actor, action_type, target, details):
    """
    Creates an action, appends a custody block, and returns new block hash.
    """
    aid, ts = log_action(db_path, actor, action_type, target, details)
    prev_hash = get_last_block_hash(db_path)

    # canonical JSON for hash stability
    action_json = json.dumps({
        "actor": actor,
        "action_type": action_type,
        "target": target,
        "details": details
    }, sort_keys=True)

    new_block_hash = append_block(db_path, aid, ts, prev_hash, action_json)
    return new_block_hash, ts
