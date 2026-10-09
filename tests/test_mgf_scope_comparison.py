"""Experimental metrics must not confuse existing exclusions with detection."""

import copy

import pytest

from experiments.compare_mgf_scope import counterfactual_changes, verify_controlled_pair
from trustlessfl.crypto import ProtocolError


def pair():
    first=dict(parent_model_hash="initial",client_update_set_sha256="updates",masked_Y_sha256="Y")
    return {s:dict(initial_model_hash="initial",rounds=[copy.deepcopy(first)])
            for s in ("projection","full-vector")}


def test_preexisting_exclusion_is_not_new_attack_detection():
    info=counterfactual_changes([5,17],[5,17],[0,1,2,3])
    assert not info["selection_changed"]
    assert info["already_rejected_attacker_ids"]==[0,1,2,3]
    assert info["newly_rejected_attacker_ids"]==[]


def test_counterfactual_reports_changes_in_both_directions():
    info=counterfactual_changes([0,1,5],[1,2,5],[0,1,2])
    assert info["newly_rejected_attacker_ids"]==[0]
    assert info["newly_accepted_attacker_ids"]==[2]
    assert info["already_rejected_attacker_ids"]==[2]


@pytest.mark.parametrize("field",["parent_model_hash","client_update_set_sha256","masked_Y_sha256"])
def test_controlled_scope_pair_rejects_nonidentical_first_round(field):
    closed=pair();closed["full-vector"]["rounds"][0][field]="different"
    with pytest.raises(ProtocolError,match="identical model/update/Y"):
        verify_controlled_pair(closed)


def test_separate_later_trajectories_are_not_required_to_be_identical():
    closed=pair()
    closed["projection"]["rounds"].append(dict(masked_Y_sha256="projection later Y"))
    closed["full-vector"]["rounds"].append(dict(masked_Y_sha256="full later Y"))
    result=verify_controlled_pair(closed)
    assert result["initial_model_equal"] and all(result["first_round_equal"].values())
