import copy
import pytest
from ecdat.ai import validate_response

def answer(summary):
    return {'summary':summary,'citations':[{'evidence_id':'E1','explanation':'Registered evidence'}],'hypotheses':[],'suggested_check':None,'limitations':[]}

@pytest.mark.parametrize('claim',[
    'The supplier expects X25519 certificate authentication.',
    'RSA authentication is not compatible with X25519 key exchange.',
    'Replace the signing algorithm with ML-KEM for signature replacement.'
])
def test_known_wrong_role_claims_rejected(claim):
    with pytest.raises(ValueError):validate_response(answer(claim),{'E1'})

def test_compatible_roles_and_explicit_negation_pass():
    assert validate_response(answer('RSA authentication can coexist with hybrid TLS key exchange. X25519 cannot provide certificate authentication.'),{'E1'})

def test_hypothesis_fields_cannot_bypass_role_rules():
    value=answer('Further evidence is needed.')
    value['hypotheses']=[{'title':'Possible cause','explanation':'X25519 certificate authentication is unsupported.','citations':[{'evidence_id':'E1','explanation':'Claim'}]}]
    with pytest.raises(ValueError):validate_response(value,{'E1'})

def test_citation_fields_cannot_bypass_role_rules():
    value=answer('Further evidence is needed.')
    value['citations'][0]['explanation']='X25519 certificate authentication is supported.'
    with pytest.raises(ValueError):validate_response(value,{'E1'})

def test_investigation_requires_competing_hypotheses_and_registered_check():
    value=answer('Further evidence is needed.')
    value['hypotheses']=[{'title':'Old observation','explanation':'The observation might predate the configuration.','citations':[{'evidence_id':'E1','explanation':'Dated observation'}]}]
    with pytest.raises(ValueError):validate_response(value,{'E1'},'investigations')

def test_grounded_investigator_rejects_invented_causes_and_preserves_roles():
    from ecdat.ai import grounded_tls_catalog,render_grounded_selection
    catalog=grounded_tls_catalog([
        {'id':'E1','claims':[{'role':'key_exchange','algorithm':'X25519','scope':'lab','parameters':{'observed_at':'2026-09-18'}}]},
        {'id':'E2','claims':[{'role':'key_exchange','algorithm':'X25519MLKEM768','scope':'lab','parameters':{'policy':'strict'}}]}])
    valid=render_grounded_selection({'ranked_hypotheses':['observation_predates_change','declaration_not_deployed']},catalog)
    assert validate_response(valid,{'E1','E2'},'investigations')['suggested_check']['check_id']=='refresh-lab-tls'
    for invalid in [{'ranked_hypotheses':['invented','declaration_not_deployed']},{'ranked_hypotheses':['declaration_not_deployed']*2},{'ranked_hypotheses':['observation_predates_change','declaration_not_deployed'],'approve':True}]:
        with pytest.raises(ValueError):render_grounded_selection(invalid,catalog)
