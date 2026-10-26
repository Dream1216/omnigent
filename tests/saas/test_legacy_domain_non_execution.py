"""Distinct native audits are neither source proof nor a guard refusal.

Only external API/gh byte transport is a fixture. Discovery, both audit
verifiers, refusal verifier, source qualifier and all-App consumer execute here.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import io
import json
import zipfile

import pytest

from saas.scripts import legacy_domain_non_execution as audit
from tests.saas.test_legacy_domain_discovery import discovery
from tests.saas.test_legacy_domain_discovery import discovery_case as discovery_case
from tests.saas.test_legacy_domain_eligibility import domain
from tests.saas.test_legacy_domain_eligibility import native_domain as native_domain
from tests.saas.test_legacy_domain_integration import current_refusal
from tests.saas.test_legacy_source_qualification import invoke, qualifier
from tests.saas.test_legacy_source_qualification import scenario as scenario


def register(scenario, run, job, check, annotations, logs):
    return {
        "kind": audit.KIND,
        "workflow_sha256": domain.MAIN_WORKFLOW_SHA256,
        **{
            key: scenario["identity"][key]
            for key in ("validation_pr", "validation_base_ref", "product_revision", "product_tree")
        },
        "event": run["event"],
        "attachment_revision": run["head_sha"],
        "run_id": run["id"],
        "attempt": run["run_attempt"],
        "job_id": job["id"],
        "check_id": check["id"],
        "run_sha256": domain.native_digest(run),
        "job_sha256": domain.native_digest(job),
        "check_sha256": domain.native_digest(check),
        "annotations_sha256": domain.native_digest(annotations),
        "run_logs_sha256": hashlib.sha256(logs).hexdigest(),
    }


@pytest.fixture
def audit_case(scenario, discovery_case, monkeypatch):
    data = discovery_case
    current_refusal(scenario, data, "default", "workflow_run")
    run, job, check = (copy.deepcopy(data[key]) for key in ("run", "job", "check"))
    run.update(
        id=8002,
        check_suite_id=9902,
        event="workflow_run",
        pull_requests=[],
        conclusion="cancelled",
    )
    prefix = f"{discovery._REPO_URL}/actions/runs/8002/attempts/1"
    run.update(jobs_url=prefix + "/jobs", logs_url=prefix + "/logs")
    job.update(
        id=9903,
        run_id=8002,
        conclusion="cancelled",
        steps=[],
        runner_id=0,
        runner_name="",
        runner_group_id=0,
        runner_group_name="",
        check_run_url=discovery._REPO_URL + "/check-runs/9904",
    )
    annotations = [
        {
            "path": ".github",
            "blob_href": f"https://github.com/Dream1216/omnigent/blob/{run['head_sha']}/.github",
            "start_line": 1,
            "end_line": 1,
            "start_column": None,
            "end_column": None,
            "annotation_level": "failure",
            "title": "",
            "raw_details": "",
            "message": "Canceling since a higher priority waiting request for "
            f"saas-n1-merge-gate-{scenario['profile']['product_revision']} exists",
        }
    ]
    check.update(
        id=9904,
        conclusion="cancelled",
        check_suite={"id": 9902},
        details_url="https://github.com/Dream1216/omnigent/actions/runs/8002/job/9903",
        output={
            "title": None,
            "summary": None,
            "text": None,
            "annotations_count": 1,
            "annotations_url": discovery._REPO_URL + "/check-runs/9904/annotations",
        },
    )
    data["runs"].append(run)
    data["jobs"][8002] = [job]
    data["checks"][9904] = check
    zero = {
        "run": run,
        "job": job,
        "check": check,
        "annotations": annotations,
        "logs": audit._EMPTY_ZIP,
    }

    def refresh():
        zero["rule"] = register(scenario, run, job, check, zero["annotations"], zero["logs"])
        scenario["policy"]["domain_non_execution"] = {domain.MAIN_WORKFLOW: [zero["rule"]]}
        return zero["rule"]

    zero["refresh"] = refresh
    refresh()
    original = discovery.api

    def api(endpoint):
        if "/annotations?" in endpoint:
            assert endpoint.endswith("per_page=100&page=1")
            return copy.deepcopy(zero["annotations"])
        return original(endpoint)

    monkeypatch.setattr(audit, "api", api)
    monkeypatch.setattr(
        audit, "download_run_logs", lambda run, attempt, path: path.write_bytes(zero["logs"])
    )
    return zero


def add_all_app_audit(scenario, data, zero):
    source = scenario["profile"]["product_revision"]
    for key in ("run", "job", "check"):
        zero[key]["head_sha"] = source
    zero["annotations"][0]["blob_href"] = (
        f"https://github.com/Dream1216/omnigent/blob/{source}/.github"
    )
    scenario["snapshots"]["head"]["runs"].append(zero["run"])
    scenario["snapshots"]["head"]["checks"].append(zero["check"])
    scenario["policy"]["other_checks"] = [
        {
            "role": "head",
            "app_id": 15368,
            "suite_id": 9902,
            "name": "evaluate",
            "scope": "original-domain-zero-execution",
            "expected_conclusion": None,
            "reason": "Exact original native zero-execution audit; source remains UNKNOWN",
        }
    ]


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize("conclusion", ["cancelled", "skipped"])
@pytest.mark.parametrize("attachment", ["default", "head"])
def test_full_typed_audit_chain_keeps_unknown_and_original_outcome(
    scenario, discovery_case, audit_case, tmp_path, conclusion, attachment
):
    zero = audit_case
    if attachment == "head":
        add_all_app_audit(scenario, discovery_case, zero)
    if conclusion == "skipped":
        for key in ("run", "job", "check"):
            zero[key]["conclusion"] = "skipped"
        zero["job"].update(
            runner_id=None, runner_name=None, runner_group_id=None, runner_group_name=None
        )
        zero["annotations"] = []
        zero["check"]["output"]["annotations_count"] = 0
    zero["refresh"]()
    result = invoke(scenario, tmp_path)
    assert result["source_ci_pass"] is True and result["complete_domain_discovery"] is True
    assert (
        result["production_admission"]
        is result["exact_product_PG_pass"]
        is result["image_admission"]
        is False
    )
    assert len(result["all_apps"]["verified_main_domain_refusals"]) == 1
    observed = result["domain_zero_execution_observations"]
    assert len(observed) == 1 and observed[0]["original_conclusion"] == conclusion
    assert observed[0]["source_classification"] == "UNKNOWN"
    assert (
        observed[0]["original_event_source_revision"]
        is observed[0]["trusted_checkout_revision"]
        is None
    )
    assert observed[0]["source_proof"] is observed[0]["guard_refusal"] is False
    assert result["all_apps"]["verified_main_domain_zero_execution"] == observed
    raw = json.loads(
        (tmp_path / "qualified/main-domain/discovery-before/domain-discovery.json").read_text()
    )
    record = next(row for row in raw["records"] if row["run_id"] == 8002)
    assert record["classification"] == "audited-nonexecution" and record["attempts"] == []
    assert raw["source_ci_pass"] is False


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize(
    "fault",
    [
        "unregistered",
        "orphaned",
        "duplicate",
        "executed-step",
        "missing-steps",
        "assigned-runner",
        "missing-runner",
        "nonempty-ZIP",
        "unavailable-ZIP",
        "wrong-check",
        "wrong-App",
        "changed-job",
        "missing-annotation",
        "false-annotation",
        "annotation-count",
        "wrong-workflow",
        "other-technical",
        "wrong-event",
        "contradictory-PR",
        "source-spoof-field",
        "success",
        "failure",
        "pending",
        "main-route",
        "wrong-product",
        "wrong-tree",
        "wrong-attempt",
        "wrong-attachment",
        "no-current-refusal",
        "technical-failure-after-Resolve",
        "new-unregistered-default",
        "forged-json",
    ],
)
def test_incomplete_changed_or_unregistered_audit_is_closed(
    scenario, discovery_case, audit_case, tmp_path, monkeypatch, fault
):
    data, zero = discovery_case, audit_case
    if fault == "unregistered":
        scenario["policy"].pop("domain_non_execution")
    elif fault == "orphaned":
        data["runs"].remove(zero["run"])
    elif fault == "duplicate":
        scenario["policy"]["domain_non_execution"][domain.MAIN_WORKFLOW].append(zero["rule"])
    elif fault == "executed-step":
        zero["job"]["steps"] = [{"name": "Set up job", "conclusion": "success"}]
    elif fault == "missing-steps":
        zero["job"].pop("steps")
    elif fault == "assigned-runner":
        zero["job"]["runner_id"] = 123
    elif fault == "missing-runner":
        zero["job"].pop("runner_id")
    elif fault == "nonempty-ZIP":
        zero["logs"] += b"extra"
    elif fault == "unavailable-ZIP":
        monkeypatch.setattr(
            audit,
            "download_run_logs",
            lambda *_: (_ for _ in ()).throw(ValueError("native logs 404")),
        )
    elif fault == "wrong-check":
        zero["check"]["check_suite"]["id"] += 1
    elif fault == "wrong-App":
        zero["check"]["app"]["id"] = 1
    elif fault == "changed-job":
        zero["job"]["extra"] = "changed native bytes"
    elif fault == "missing-annotation":
        zero["annotations"] = []
    elif fault == "false-annotation":
        zero["annotations"][0]["message"] = "cancelled for a technical failure"
    elif fault == "annotation-count":
        zero["check"]["output"]["annotations_count"] = 0
    elif fault in {"wrong-workflow", "other-technical"}:
        zero["run"]["path"] = ".github/workflows/ci.yml"
    elif fault == "wrong-event":
        zero["rule"]["event"] = "push"
    elif fault == "contradictory-PR":
        zero["run"]["pull_requests"] = [
            {
                "number": scenario["identity"]["validation_pr"],
                "url": discovery._REPO_URL + "/pulls/9001",
            },
            {"number": 189, "url": discovery._REPO_URL + "/pulls/189"},
        ]
    elif fault == "source-spoof-field":
        zero["rule"]["original_event_source_revision"] = scenario["profile"]["product_revision"]
    elif fault in {"success", "failure"}:
        zero["run"]["conclusion"] = fault
    elif fault == "pending":
        zero["run"]["status"] = "queued"
    elif fault == "main-route":
        scenario["pull"]["base"]["ref"] = "main"
    elif fault == "wrong-product":
        zero["rule"]["product_revision"] = "f" * 40
    elif fault == "wrong-tree":
        zero["rule"]["product_tree"] = "f" * 40
    elif fault == "wrong-attempt":
        zero["rule"]["attempt"] = 2
    elif fault == "wrong-attachment":
        zero["rule"]["attachment_revision"] = "f" * 40
    elif fault == "no-current-refusal":
        scenario["policy"]["domain_not_applicable"] = {}
    elif fault == "technical-failure-after-Resolve":
        data["job"]["steps"][1]["conclusion"] = "success"
        data["job"]["steps"][2]["conclusion"] = "failure"
        data["refresh_rule"]()
    elif fault == "new-unregistered-default":
        run = copy.deepcopy(zero["run"])
        run["id"] = 8003
        data["runs"].append(run)
    elif fault == "forged-json":
        original = domain.discover_main_domain
        monkeypatch.setattr(domain, "discover_main_domain", lambda *a: dict(original(*a)))
    with pytest.raises((ValueError, KeyError)):
        invoke(scenario, tmp_path)
    assert not (tmp_path / "qualified/source-qualification.json").exists()


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize(
    "fault", ["json-proof", "no-refusal", "changed-snapshot", "downgraded-scope"]
)
def test_all_app_requires_typed_exact_audit_and_independent_refusal(
    scenario, discovery_case, audit_case, tmp_path, monkeypatch, fault
):
    add_all_app_audit(scenario, discovery_case, audit_case)
    audit_case["refresh"]()
    original = qualifier.assess_all_app_policy

    def altered(snapshots, observations, policy, refusals=None, audits=()):
        if fault == "json-proof":
            audits = tuple(row.receipt for row in audits)
        elif fault == "no-refusal":
            refusals = []
        elif fault == "changed-snapshot":
            snapshots = copy.deepcopy(snapshots)
            next(row for row in snapshots["head"]["checks"] if row["id"] == 9904)["extra"] = (
                "changed"
            )
        else:
            policy["other_checks"][0]["scope"] = "original-informational"
        return original(snapshots, observations, policy, refusals, audits)

    monkeypatch.setattr(qualifier, "assess_all_app_policy", altered)
    with pytest.raises(ValueError):
        invoke(scenario, tmp_path)


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize("scope", ["main", "unknown-component"])
def test_audit_native_predicate_rejects_nonlegacy_scope(scenario, audit_case, scope):
    identity = copy.deepcopy(scenario["identity"])
    profile = copy.deepcopy(scenario["profile"])
    rule = copy.deepcopy(audit_case["rule"])
    if scope == "main":
        identity["validation_base_ref"] = rule["validation_base_ref"] = "main"
    else:
        profile["component"] = "unknown-component"
    with pytest.raises(ValueError, match="exact frozen legacy domain"):
        audit.verify_zero_execution(
            profile,
            identity,
            rule,
            audit_case["run"],
            audit_case["job"],
            audit_case["check"],
            audit_case["annotations"],
            audit_case["logs"],
        )


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
def test_zero_only_discovery_never_creates_eligibility(
    scenario, discovery_case, audit_case, tmp_path
):
    discovery_case["runs"].remove(discovery_case["run"])
    path = tmp_path / "audit-only"
    path.mkdir()
    result = discovery.discover_main_domain(
        scenario["profile"], scenario["identity"], [], path, [audit_case["rule"]]
    )
    assert result["complete_discovery"] is True and len(result.observations) == 1
    assert result["source_ci_pass"] is result["domain_eligibility"] is False
    scenario["policy"]["domain_not_applicable"] = {}
    with pytest.raises(ValueError):
        domain.collect_domain_eligibility(
            scenario["profile"], scenario["identity"], scenario["policy"], tmp_path / "eligibility"
        )


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
def test_mutable_native_PR_head_and_concurrency_group_are_not_source_proof(scenario, audit_case):
    zero = audit_case
    zero["run"]["pull_requests"] = [
        {
            "number": scenario["identity"]["validation_pr"],
            "url": discovery._REPO_URL + "/pulls/9001",
            "head": {"sha": "b" * 40},
        }
    ]
    zero["refresh"]()
    proof = audit.verify_zero_execution(
        scenario["profile"],
        scenario["identity"],
        zero["rule"],
        zero["run"],
        zero["job"],
        zero["check"],
        zero["annotations"],
        zero["logs"],
    )
    assert proof.receipt["source_classification"] == "UNKNOWN"
    assert proof.receipt["original_event_source_revision"] is None
    assert proof.receipt["source_proof"] is False


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize("change", ["check", "annotation", "ZIP"])
def test_zero_execution_native_proof_is_refreshed(
    scenario, audit_case, tmp_path, monkeypatch, change
):
    original = audit.collect_zero_execution
    calls = 0

    def changed(*args):
        nonlocal calls
        proof = original(*args)
        calls += 1
        if calls == 1:
            if change == "check":
                audit_case["check"]["extra"] = "late native change"
            elif change == "annotation":
                audit_case["annotations"][0]["message"] += " changed"
            else:
                audit_case["logs"] += b"changed"
        return proof

    monkeypatch.setattr(audit, "collect_zero_execution", changed)
    with pytest.raises(ValueError):
        invoke(scenario, tmp_path)
    assert calls >= 1


# Reviewed native archive from the setup/partial-checkout cancellation. API tuples
# below remain owned fixtures; this is neither a native execution nor clearance.
_INFRASTRUCTURE_LOG_ZIP = base64.b85decode(
    b"P)h>@6aWYS2mk;8000000000000000000gE001ywWp-g~bzyX6E_8TwoLB#D+_(|`|DIxiL*X`nwEQVi0t(cZT$7-"
    b"^#;~0h&>=Wb((JBkNz{>47H-ie>mPljzCuB1*YO>ewwwQK?Dx%lGxKRk{`cSiVT5G~B?*(ajFqG)X_n@a5Jgo5uV-"
    b"s<^kC<4L<^tMy3ULxT(FdLm6D5Z&eIuTN>uRew?FQznWs<JEC2nVcL-"
    b"P3eC|RVv{8B?Nd@nW^Vq^`GfcBbxZL6BV+_iPs^G6DfdNGcqiIG}l#=Cn6`~KFFM&}>q;8oMw3RhxluK-"
    b"t*fyMJMNUQ5Y;##Fj74L#P!)VPcYO<Qw8vG$0;IQultPw_R#A3FX$5~X_Aa#PO$q<3>n#&?-"
    b"6m8smI%_&q>znFv}RfoB4}Rof5pOaQsfm}<8Eoj0iB;6kAel~6};}v+?H_pkJ(0R<hd-Csp8nKgN-"
    b"3Y#`8z>|1hD|z8iONbMHJ3F`6WlRPeE$M?Xg~JQEc#krI*0D5#KG1%JN1i2*W}=PxTI%M^`RIY!AzuBsJM!n{<IEP|s15pw*"
    b">y)=AeBBe2sVuDxjer)==#TIVN)*rOR687FtuH0;Po!`%O+L&RZ8{e7HZPpJt>4G%3se4mzR((ut9%tPg5$lhek4Fp<$u;VB"
    b"z;tM1vI<5|#ltoBsNMe~$*v5y@p|_l?KkX?kHtkZtKgm&%#@RyJhtcC_qXppe)rSuhd+J)7q~(@bS@0S#psOCtb)t6fD$a~S"
    b"T{Hmf`%nCdK~?8SVctzKcLsG_WEforx~r_YVP}M{CP(ATx>2yR>6(ees<_eIM~j|{L8s2Uf4*<MNz>GHWocNGusBsQ)6PBjD"
    b"}VHS~q)y!L<0a@JxnHa%FMS7U5v*-"
    b"L^LeXgiCIH}?K4PqCckl6~Rnz6Xmx&z;2<^b`6NCz2Mtg16|Gg|&jAHHWb`x`l4snlsEiB}#G5iwfSHphv33$+#|Pg^QEvn>"
    b"{vnX7+z58dA`@X0*;5+R&C3;opL&Ruw3)Xxny+9LWXz_U7GX`BM1r&PwFD5<<%5(3^Vn2!A&<jC#Nl@U!k`eby6sDzd!D75U"
    b"{Fgs(0pl0y+5OnT`2zKlX-UQ_^Jaa+QmyD<t>1r0zqY3ndKX)GaKchJNBY0NNbpSZ!?VdAuQ$w-"
    b"r3yc3GDe2F}Tb?to8SZs0ho$g%;Tiv@jQ_7?GlOsxaV^I&3(QIRev5Q=B7B<haJg~jF!?A={uU<uw1zV8L?Gxv1*Z2~=ouj%"
    b"0T`LOs*`Y0A*F|LrL6#z#9`*Q4+-"
    b"$A)S2IW&Gh(uS`cKje$pd|hzS$=&PJUm)x#Ms_OIl=K&|dGJn}!s@(Ex654#{NA&Z2WqE0RjdK<T&71<xp5M=;leY3ClFCGd"
    b"PzgFbP3i^;==ds<SKNfmgy@692Z$AvrDM}~hgZBDZ1??HJg1?NJs3U2PlCalG;u&@+7+)N*zyT={-w)3aAMSQ<X!85{-"
    b"x8%TjXb^M`E;f5J;PEoC3CF~Pn1?^ky;jz^%lGnQV}?PG?WfJ`?56I<a9cU)ickwBgs9*V5LhZ@dVa-"
    b"8Nfiy3?dSU~S)LWLf?FIWW3}!2doZ8T+O7??zx(jR_rE_=^G_a!X(JmZgsN%6a?KM_WICyfS|(JomPn=ZTIUx~<JMS&K`-"
    b"6h^`_SSQb}XRZMTDFug4vpJ0=%>1qp_|Y};Sj;n7&U0l!D^#}e+B;Kw}29NK|~VA&@R^pKA;#iK(yMoW@o^d!-"
    b"3yTnbu$a#T7&gRajC=^@Y0BEhTpKkXEW_{9_5f0ixqsIn&Y}4}*3L+`v6<itTmos-"
    b"+p7V4bo@Y5H#quUYJ%;wq6Bs+~^$3$S4LXPJoBss>0RR6`O9u$!A|JSi1polN4*&pAO9KQH00;mG00000000000000000000"
    b"022TJ0A+SzY;|FDWiNAib97~GE_8Twtdh@))Ibo2?><F&*(8T_{xI3qz<`3Hcw7X*%TP%wNxPluv8#GVVIN**f~+I!=)qglU"
    b"G?=>{HiYN>%1!Sy7^ewZTYgTHfFQADa*3_47c<(k|+(}up=ie#4fVN+@X@_vy06id<O%KmT3Ug7TyHHrK+pz!Y^zmVlB*Mb&"
    b"g$e@ZoNB{vd@QO3qcjP?#v6P|18>+^ayN6f@x<#e$YEfBXrpTApC^0T4oDrU2?;Z~Hrld(hbmeDR$z<`1A|1--pT7xBcR^+?"
    b"8!|Ju_+DzWcLB+cOJ3eq%P$2D|MtUJbq;Q1DkpVRL`<RpWK2RJJ<zrL?mu-"
    b"!tkkIwDFnoyEuS@svPZ+ql{h89u{kyfKK$WAd#q{;u3y6kjI5}mei6ne6<xoIAk$qF3KqMiL|Hy;!3{X*c`S*E9>{hf!Mk9z"
    b"DB#h@qB5$_pvrgMG^@2tL$9lY+<dKRdTq!-"
    b"nuX?_F%0RR6`O9u#tT{}c?0RR9*0{{R}O928D02BZS00;m80002vA|JSi1polN4*&oT0000000000000000000005D%=c42I"
    b"FVRU6Kba-"
    b"@7O928D02BZS00;m80001oT{}c?0RR9*0{{RM0000000000000000K)|U0A+SzY;|FDWiNAib97~GE_8TwP)h{{000000ssO"
    b"4eE<Lea|Zwb000"
)
_INFRASTRUCTURE_NATIVE_STEPS = [
    {
        "name": "Set up job",
        "status": "completed",
        "conclusion": "success",
        "number": 1,
        "started_at": "2026-10-25T22:09:16Z",
        "completed_at": "2026-10-25T22:09:17Z",
    },
    {
        "name": "Check out trusted gate",
        "status": "completed",
        "conclusion": "cancelled",
        "number": 2,
        "started_at": "2026-10-25T22:09:17Z",
        "completed_at": "2026-10-25T22:09:17Z",
    },
    {
        "name": "Resolve current PR head",
        "status": "completed",
        "conclusion": "skipped",
        "number": 3,
        "started_at": "2026-10-25T22:09:17Z",
        "completed_at": "2026-10-25T22:09:17Z",
    },
    {
        "name": "Evaluate exact PostgreSQL N-1 authority",
        "status": "completed",
        "conclusion": "skipped",
        "number": 4,
        "started_at": "2026-10-25T22:09:17Z",
        "completed_at": "2026-10-25T22:09:17Z",
    },
    {
        "name": "Mark non-completed N-1 run pending",
        "status": "completed",
        "conclusion": "skipped",
        "number": 5,
        "started_at": "2026-10-25T22:09:17Z",
        "completed_at": "2026-10-25T22:09:17Z",
    },
    {
        "name": "Post exact-head gate status",
        "status": "completed",
        "conclusion": "skipped",
        "number": 6,
        "started_at": "2026-10-25T22:09:17Z",
        "completed_at": "2026-10-25T22:09:17Z",
    },
    {
        "name": "Post Check out trusted gate",
        "status": "completed",
        "conclusion": "success",
        "number": 12,
        "started_at": "2026-10-25T22:09:17Z",
        "completed_at": "2026-10-25T22:09:17Z",
    },
    {
        "name": "Complete job",
        "status": "completed",
        "conclusion": "success",
        "number": 13,
        "started_at": "2026-10-25T22:09:17Z",
        "completed_at": "2026-10-25T22:09:17Z",
    },
]


def add_ubuntu26_notice(zero):
    zero["annotations"].append(
        {
            "path": ".github",
            "blob_href": f"https://github.com/Dream1216/omnigent/blob/{zero['run']['head_sha']}/.github",
            "start_line": 1,
            "end_line": 1,
            "start_column": None,
            "end_column": None,
            "annotation_level": "notice",
            "title": "",
            "raw_details": "",
            "message": (
                '"The ubuntu-latest label will migrate to Ubuntu 26 '
                "beginning October 19, 2026. For more information, see "
                'https://github.com/actions/runner-images/issues/14748"'
            ),
        }
    )
    zero["check"]["output"]["annotations_count"] = len(zero["annotations"])


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
def test_exact_native_runner_notice_preserves_zero_execution_contract(
    scenario, discovery_case, audit_case, tmp_path
):
    zero = audit_case
    add_all_app_audit(scenario, discovery_case, zero)
    add_ubuntu26_notice(zero)
    zero["refresh"]()
    result = invoke(scenario, tmp_path)
    proof = result["domain_zero_execution_observations"][0]
    assert proof["annotations_sha256"] == domain.native_digest(zero["annotations"])
    assert proof["execution"] == "native-proven-zero"
    assert proof["source_proof"] is proof["guard_refusal"] is False
    assert result["all_apps"]["verified_main_domain_zero_execution"] == [proof]
    assert result["domain_infrastructure_cancellation_observations"] == []


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize(
    "fault",
    ["message", "level", "blob", "line", "extra-field", "duplicate", "order", "missing-failure"],
)
def test_runner_notice_is_exact_ordered_complete_native_metadata(
    scenario, audit_case, tmp_path, fault
):
    zero = audit_case
    add_ubuntu26_notice(zero)
    notice = zero["annotations"][-1]
    if fault == "message":
        notice["message"] += " unreviewed"
    elif fault == "level":
        notice["annotation_level"] = "warning"
    elif fault == "blob":
        notice["blob_href"] = "https://github.com/Dream1216/omnigent/blob/" + "f" * 40 + "/.github"
    elif fault == "line":
        notice["start_line"] = notice["end_line"] = 2
    elif fault == "extra-field":
        notice["unreviewed"] = True
    elif fault == "duplicate":
        zero["annotations"].append(copy.deepcopy(notice))
    elif fault == "order":
        zero["annotations"].reverse()
    else:
        zero["annotations"].pop(0)
    zero["check"]["output"]["annotations_count"] = len(zero["annotations"])
    zero["refresh"]()
    with pytest.raises(ValueError):
        invoke(scenario, tmp_path)
    assert not (tmp_path / "qualified/source-qualification.json").exists()


@pytest.fixture
def infrastructure_case(scenario, discovery_case, audit_case, monkeypatch):
    observed = audit_case
    observed["run"]["event"] = "pull_request_target"
    observed["job"].update(
        runner_id=1000081455,
        runner_name="GitHub Actions 1000081455",
        runner_group_id=0,
        runner_group_name="GitHub Actions",
        started_at="2026-10-25T22:09:15Z",
        completed_at="2026-10-25T22:09:20Z",
        steps=copy.deepcopy(_INFRASTRUCTURE_NATIVE_STEPS),
    )
    # A concurrency key is an audit fact, never an original event source.
    observed["annotations"][0]["message"] = (
        "Canceling since a higher priority waiting request for "
        f"saas-n1-merge-gate-{observed['run']['head_sha']} exists"
    )
    operation = copy.deepcopy(observed["annotations"][0])
    operation.update(start_line=29, end_line=29, message="The operation was canceled.")
    observed["annotations"].append(operation)
    add_ubuntu26_notice(observed)
    observed["logs"] = _INFRASTRUCTURE_LOG_ZIP
    scenario["policy"].pop("domain_non_execution")

    def refresh():
        observed["rule"] = register(
            scenario,
            observed["run"],
            observed["job"],
            observed["check"],
            observed["annotations"],
            observed["logs"],
        )
        observed["rule"]["kind"] = audit.INFRASTRUCTURE_KIND
        scenario["policy"]["domain_infrastructure_cancellation"] = {
            domain.MAIN_WORKFLOW: [observed["rule"]]
        }
        return observed["rule"]

    observed["refresh"] = refresh
    refresh()
    monkeypatch.setattr(
        audit,
        "download_infrastructure_run_logs",
        lambda run, attempt, path: path.write_bytes(observed["logs"]),
    )
    return observed


def add_all_app_infrastructure(scenario, data, observed):
    add_all_app_audit(scenario, data, observed)
    source = observed["run"]["head_sha"]
    for annotation in observed["annotations"]:
        annotation["blob_href"] = f"https://github.com/Dream1216/omnigent/blob/{source}/.github"
    observed["annotations"][0]["message"] = (
        f"Canceling since a higher priority waiting request for saas-n1-merge-gate-{source} exists"
    )
    scenario["policy"]["other_checks"][0].update(
        scope="original-domain-infrastructure-cancellation",
        reason="Exact native infrastructure cancellation; checkout/source UNKNOWN; no gate waiver",
    )


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize("attachment", ["default", "head"])
def test_typed_infrastructure_audit_never_becomes_zero_or_source_refusal(
    scenario, discovery_case, infrastructure_case, tmp_path, attachment
):
    observed = infrastructure_case
    if attachment == "head":
        add_all_app_infrastructure(scenario, discovery_case, observed)
    observed["refresh"]()
    result = invoke(scenario, tmp_path)
    proof = result["domain_infrastructure_cancellation_observations"][0]
    assert proof["kind"] == audit.INFRASTRUCTURE_KIND
    assert proof["execution"] == "native-infrastructure-executed-cancelled"
    assert proof["git_executed"] is True
    assert proof["source_classification"] == proof["checkout_classification"] == "UNKNOWN"
    assert proof["original_event_source_revision"] is proof["trusted_checkout_revision"] is None
    assert (
        proof["source_proof"]
        is proof["guard_refusal"]
        is proof["technical_gate_waiver"]
        is proof["production_admission"]
        is False
    )
    assert proof["original_conclusion"] == "cancelled"
    assert proof["run_logs_sha256"] == hashlib.sha256(_INFRASTRUCTURE_LOG_ZIP).hexdigest()
    assert result["domain_zero_execution_observations"] == []
    assert result["all_apps"]["verified_main_domain_zero_execution"] == []
    assert result["all_apps"]["verified_main_domain_infrastructure_cancellations"] == [proof]
    assert len(result["all_apps"]["verified_main_domain_refusals"]) == 1
    if attachment == "head":
        assert result["all_apps"]["original_informational_checks"] == []
        assert (
            result["all_apps"]["original_infrastructure_cancellations"][0]["conclusion"]
            == "cancelled"
        )
    raw = json.loads(
        (tmp_path / "qualified/main-domain/discovery-before/domain-discovery.json").read_text()
    )
    record = next(row for row in raw["records"] if row["run_id"] == 8002)
    assert record["classification"] == "audited-infrastructure-cancellation"
    assert record["attempts"] == [] and record.get("non_execution_observations", []) == []
    assert raw["source_ci_pass"] is raw["domain_eligibility"] is False
    assert result["source_ci_pass"] is True and result["production_admission"] is False


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize(
    "fault",
    [
        "Resolve-executed",
        "gate-executed",
        "extra-business-step",
        "step-order",
        "step-time",
        "unknown-runner",
        "wrong-event",
        "nonconcurrency",
        "missing-operation",
        "missing-notice",
        "duplicate-notice",
        "extra-command-in-ZIP",
        "extra-member-in-ZIP",
        "unregistered",
        "orphaned",
        "duplicate-rule",
        "no-current-refusal",
        "zero-scope",
        "forged-json",
    ],
)
def test_infrastructure_cancellation_rejects_even_rehashed_unsafe_input(
    scenario, discovery_case, infrastructure_case, tmp_path, monkeypatch, fault
):
    observed = infrastructure_case
    add_all_app_infrastructure(scenario, discovery_case, observed)
    if fault == "Resolve-executed":
        observed["job"]["steps"][2]["conclusion"] = "failure"
    elif fault == "gate-executed":
        observed["job"]["steps"][3]["conclusion"] = "success"
    elif fault == "extra-business-step":
        observed["job"]["steps"].append(
            {
                **observed["job"]["steps"][-1],
                "number": 14,
                "name": "Run product",
                "conclusion": "success",
            }
        )
    elif fault == "step-order":
        observed["job"]["steps"][2:4] = reversed(observed["job"]["steps"][2:4])
    elif fault == "step-time":
        observed["job"]["steps"][2]["started_at"] = "2026-10-25T22:09:16Z"
    elif fault == "unknown-runner":
        observed["job"]["runner_id"] += 1
    elif fault == "wrong-event":
        observed["run"]["event"] = "workflow_run"
    elif fault == "nonconcurrency":
        observed["annotations"][0]["message"] = "technical execution failed"
    elif fault == "missing-operation":
        observed["annotations"].pop(1)
    elif fault == "missing-notice":
        observed["annotations"].pop()
    elif fault == "duplicate-notice":
        observed["annotations"].append(copy.deepcopy(observed["annotations"][-1]))
    elif fault in {"extra-command-in-ZIP", "extra-member-in-ZIP"}:
        changed = io.BytesIO()
        with (
            zipfile.ZipFile(io.BytesIO(observed["logs"])) as original,
            zipfile.ZipFile(changed, "w", zipfile.ZIP_DEFLATED) as output,
        ):
            for name in original.namelist():
                body = original.read(name)
                if fault == "extra-command-in-ZIP" and name == "0_evaluate.txt":
                    body += (
                        b"2026-10-25T22:09:17.7000000Z [command]/bin/bash "
                        b".github/actions/compat-smoke-saas-n1-gate/evaluate.sh\n"
                    )
                output.writestr(name, body)
            if fault == "extra-member-in-ZIP":
                output.writestr("evaluate/3_Resolve current PR head.txt", b"executed guard")
        observed["logs"] = changed.getvalue()
    # The attacker recomputes every native tuple and log hash; semantic guards must still reject.
    observed["check"]["output"]["annotations_count"] = len(observed["annotations"])
    observed["refresh"]()
    if fault == "unregistered":
        scenario["policy"].pop("domain_infrastructure_cancellation")
    elif fault == "orphaned":
        discovery_case["runs"].remove(observed["run"])
    elif fault == "duplicate-rule":
        scenario["policy"]["domain_infrastructure_cancellation"][domain.MAIN_WORKFLOW].append(
            observed["rule"]
        )
    elif fault == "no-current-refusal":
        scenario["policy"]["domain_not_applicable"] = {}
    elif fault == "zero-scope":
        scenario["policy"]["other_checks"][0]["scope"] = "original-domain-zero-execution"
    elif fault == "forged-json":
        original = domain.discover_main_domain
        monkeypatch.setattr(domain, "discover_main_domain", lambda *a: dict(original(*a)))
    with pytest.raises(ValueError):
        invoke(scenario, tmp_path)
    assert not (tmp_path / "qualified/source-qualification.json").exists()


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize(
    "field", ["validation_pr", "validation_base_ref", "product_tree", "source_head"]
)
def test_infrastructure_all_app_requires_same_current_guard_identity(
    scenario, discovery_case, infrastructure_case, tmp_path, monkeypatch, field
):
    add_all_app_infrastructure(scenario, discovery_case, infrastructure_case)
    infrastructure_case["refresh"]()
    original = qualifier.assess_all_app_policy

    def altered(snapshots, observations, policy, refusals=None, audits=()):
        refusals = copy.deepcopy(refusals)
        refusals[0][field] = 123 if field == "validation_pr" else "different"
        return original(snapshots, observations, policy, refusals, audits)

    monkeypatch.setattr(qualifier, "assess_all_app_policy", altered)
    with pytest.raises(ValueError, match="same-PR/base/tree/product"):
        invoke(scenario, tmp_path)


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize("change", ["check", "annotation", "ZIP"])
def test_infrastructure_native_proof_is_refreshed(
    scenario, infrastructure_case, tmp_path, monkeypatch, change
):
    original = audit.collect_infrastructure_cancellation
    calls = 0

    def changed(*args):
        nonlocal calls
        proof = original(*args)
        calls += 1
        if calls == 1:
            if change == "check":
                infrastructure_case["check"]["extra"] = "late native change"
            elif change == "annotation":
                infrastructure_case["annotations"][-1]["message"] += " changed"
            else:
                infrastructure_case["logs"] += b"changed"
        return proof

    monkeypatch.setattr(audit, "collect_infrastructure_cancellation", changed)
    with pytest.raises(ValueError):
        invoke(scenario, tmp_path)
    assert calls >= 1


@pytest.mark.parametrize("scenario", [{"main_domain": True}], indirect=True)
@pytest.mark.parametrize("fault", ["json-proof", "wrong-type", "changed-run"])
def test_infrastructure_all_app_rejects_relabelled_or_changed_native_proof(
    scenario, discovery_case, infrastructure_case, tmp_path, monkeypatch, fault
):
    add_all_app_infrastructure(scenario, discovery_case, infrastructure_case)
    infrastructure_case["refresh"]()
    original = qualifier.assess_all_app_policy

    def altered(snapshots, observations, policy, refusals=None, audits=()):
        if fault == "json-proof":
            audits = tuple(row.receipt for row in audits)
        elif fault == "wrong-type":
            audits = tuple(audit.ZeroExecutionObservation(row.receipt) for row in audits)
        else:
            snapshots = copy.deepcopy(snapshots)
            next(row for row in snapshots["head"]["runs"] if row["id"] == 8002)["extra"] = (
                "changed"
            )
        return original(snapshots, observations, policy, refusals, audits)

    monkeypatch.setattr(qualifier, "assess_all_app_policy", altered)
    with pytest.raises(ValueError):
        invoke(scenario, tmp_path)
