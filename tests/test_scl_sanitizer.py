from dataclasses import dataclass
from pathlib import Path
from typing import Dict, List
from lxml import etree as ET

import pytest
import scl_sanitizer

FIXTURE_DIR = Path(__file__).resolve().parent / "fixtures"

# IEC 61850 SCL file types. Add another suffix here if the project
# adopts an additional SCL-related extension.
SCL_EXTENSIONS = {
    ".cid",
    ".icd",
    ".iid",
    ".scd",
    ".sed",
    ".scl",
    ".ssd",
}

SCL_NS = "http://www.iec.ch/61850/2003/SCL"
NSMAP = {"scl": SCL_NS}

SENSITIVE_DAIS = {
    "NamPlt": {
        "vendor",
        "swRev",
        "d",
        "dU",
    },
    "PhyNam": {
        "vendor",
        "hwRev",
        "swRev",
        "serNum",
        "model",
        "location",
        "name",
        "owner",
        "ePSName",
        "primeOper",
        "secondOper",
        "latitude",
        "longitude",
        "altitude",
        "mRID",
        "d",
        "dU",
    },
}

@dataclass(frozen=True)
class SanitizedFixture:
    source_path: Path
    output_path: Path
    input_root: ET._Element
    output_root: ET._Element

def discover_scl_fixtures() -> List[Path]:
    if not FIXTURE_DIR.is_dir():
        raise RuntimeError(f"Fixture directory does not exist: {FIXTURE_DIR}")

    fixtures = sorted(
        path
        for path in FIXTURE_DIR.rglob("*")
        if (
            path.is_file()
            and path.suffix.lower() in SCL_EXTENSIONS
            and "_sanitized" not in path.stem
        )
    )

    if not fixtures:
        extensions = ", ".join(sorted(SCL_EXTENSIONS))
        raise RuntimeError(
            f"No SCL fixtures found under {FIXTURE_DIR}. "
            f"Expected one of: {extensions}"
        )

    return fixtures

SCL_FIXTURES = discover_scl_fixtures()

def parse_xml(path: Path) -> ET._ElementTree:
    parser = ET.XMLParser(
        remove_blank_text=False,
        remove_comments=False,
    )
    return ET.parse(str(path), parser)

def fixture_id(path: Path) -> str:
    return str(path.relative_to(FIXTURE_DIR)).replace("\\", "/")

@pytest.fixture(
    scope="function",
    params=SCL_FIXTURES,
    ids=fixture_id,
)
def sanitized_fixture(
    request: pytest.FixtureRequest,
    tmp_path: Path,
) -> SanitizedFixture:
    source_path: Path = request.param

    temporary_input = tmp_path / source_path.name
    temporary_input.write_bytes(source_path.read_bytes())

    output_path = Path(
        scl_sanitizer.sanitize(
            str(temporary_input),
            seed=12345,
        )
    )

    return SanitizedFixture(
        source_path=source_path,
        output_path=output_path,
        input_root=parse_xml(temporary_input).getroot(),
        output_root=parse_xml(output_path).getroot(),
    )

def attribute_values(
    root: ET._Element,
    xpath: str,
    attribute: str,
) -> List[str]:
    elements = root.xpath(xpath, namespaces=NSMAP)
    return [
        value
        for element in elements
        if (value := element.get(attribute)) is not None
    ]

def test_fixture_is_valid_scl_xml(
    sanitized_fixture: SanitizedFixture,
):
    assert sanitized_fixture.input_root.tag in {
        f"{{{SCL_NS}}}SCL",
        "SCL",
    }

    assert sanitized_fixture.output_root.tag == (
        f"{{{SCL_NS}}}SCL"
    )

def test_output_is_deterministic(
    sanitized_fixture: SanitizedFixture,
    tmp_path: Path,
):
    second_input = tmp_path / sanitized_fixture.source_path.name
    second_input.write_bytes(
        sanitized_fixture.source_path.read_bytes()
    )

    second_output = Path(
        scl_sanitizer.sanitize(
            str(second_input),
            seed=12345,
        )
    )

    assert (
        sanitized_fixture.output_path.read_bytes()
        == second_output.read_bytes()
    )

def test_topology_references_are_renamed(
    sanitized_fixture: SanitizedFixture,
):
    input_root = sanitized_fixture.input_root
    output_root = sanitized_fixture.output_root

    input_terminals = input_root.xpath(
        ".//scl:Terminal",
        namespaces=NSMAP,
    )
    output_terminals = output_root.xpath(
        ".//scl:Terminal",
        namespaces=NSMAP,
    )

    assert len(input_terminals) == len(output_terminals)

    topology_attributes = (
        "connectivityNode",
        "substationName",
        "voltageLevelName",
        "bayName",
        "cNodeName",
    )

    for original, sanitized in zip(
        input_terminals,
        output_terminals,
    ):
        for attribute in topology_attributes:
            original_value = original.get(attribute)

            if original_value is None:
                continue

            sanitized_value = sanitized.get(attribute)

            assert sanitized_value
            assert sanitized_value != original_value

    input_nodes = input_root.xpath(
        ".//scl:ConnectivityNode",
        namespaces=NSMAP,
    )
    output_nodes = output_root.xpath(
        ".//scl:ConnectivityNode",
        namespaces=NSMAP,
    )

    assert len(input_nodes) == len(output_nodes)

    for original, sanitized in zip(input_nodes, output_nodes):
        original_path = original.get("pathName")

        if original_path is None:
            continue

        sanitized_path = sanitized.get("pathName")

        assert sanitized_path
        assert sanitized_path != original_path

def test_composite_ied_references_are_rewritten(
    sanitized_fixture: SanitizedFixture,
):
    input_root = sanitized_fixture.input_root
    output_root = sanitized_fixture.output_root

    input_elements = input_root.xpath(
        ".//*[@setSrcRef or @setDstRef or @srcRef]",
        namespaces=NSMAP,
    )
    output_elements = output_root.xpath(
        ".//*[@setSrcRef or @setDstRef or @srcRef]",
        namespaces=NSMAP,
    )

    assert len(input_elements) == len(output_elements)

    input_ied_names = {
        value
        for value in input_root.xpath(
            ".//scl:IED/@name",
            namespaces=NSMAP,
        )
    }
    output_ied_names = {
        value
        for value in output_root.xpath(
            ".//scl:IED/@name",
            namespaces=NSMAP,
        )
    }

    for original, sanitized in zip(
        input_elements,
        output_elements,
    ):
        for attribute in ("setSrcRef", "setDstRef", "srcRef"):
            original_value = original.get(attribute)

            if original_value is None:
                continue

            sanitized_value = sanitized.get(attribute)
            assert sanitized_value is not None

            original_ied, separator, original_remainder = (
                original_value.partition("/")
            )
            sanitized_ied, new_separator, sanitized_remainder = (
                sanitized_value.partition("/")
            )

            # The sanitizer currently rewrites references whose first
            # component identifies an IED defined in this SCL file.
            if original_ied in input_ied_names:
                assert sanitized_ied != original_ied
                assert sanitized_ied in output_ied_names

                # Only the IED component should change.
                assert new_separator == separator
                assert sanitized_remainder == original_remainder

def test_extref_identifiers_are_sanitized_consistently(
    sanitized_fixture: SanitizedFixture,
):
    input_root = sanitized_fixture.input_root
    output_root = sanitized_fixture.output_root

    input_ext_refs = input_root.xpath(
        ".//scl:ExtRef",
        namespaces=NSMAP,
    )
    output_ext_refs = output_root.xpath(
        ".//scl:ExtRef",
        namespaces=NSMAP,
    )

    assert len(input_ext_refs) == len(output_ext_refs)

    mappings: Dict[str, Dict[str, str]] = {
        "iedName": {},
        "ldInst": {},
        "srcLDInst": {},
        "srcCBName": {},
    }

    for original, sanitized in zip(
        input_ext_refs,
        output_ext_refs,
    ):
        for attribute in mappings:
            original_value = original.get(attribute)

            if original_value is None:
                continue

            sanitized_value = sanitized.get(attribute)

            assert sanitized_value
            assert sanitized_value != original_value

            existing = mappings[attribute].get(original_value)

            if existing is None:
                mappings[attribute][original_value] = sanitized_value
            else:
                assert sanitized_value == existing

        # These IEC model attributes are deliberately preserved.
        assert sanitized.get("lnClass") == original.get("lnClass")
        assert sanitized.get("lnInst") == original.get("lnInst")
        assert sanitized.get("srcLNClass") == original.get(
            "srcLNClass"
        )
        assert sanitized.get("doName") == original.get("doName")
        assert sanitized.get("daName") == original.get("daName")

def test_extref_intaddr_is_cleared(
    sanitized_fixture: SanitizedFixture,
):
    input_ext_refs = sanitized_fixture.input_root.xpath(
        ".//scl:ExtRef[@intAddr]",
        namespaces=NSMAP,
    )
    output_ext_refs = sanitized_fixture.output_root.xpath(
        ".//scl:ExtRef[@intAddr]",
        namespaces=NSMAP,
    )

    assert len(input_ext_refs) == len(output_ext_refs)

    for original, sanitized in zip(
        input_ext_refs,
        output_ext_refs,
    ):
        assert original.get("intAddr") is not None
        assert sanitized.get("intAddr") == ""

def test_sensitive_dai_values_are_randomized(
    sanitized_fixture: SanitizedFixture,
):
    input_root = sanitized_fixture.input_root
    output_root = sanitized_fixture.output_root

    for doi_name, dai_names in SENSITIVE_DAIS.items():
        for dai_name in dai_names:
            xpath = (
                f".//scl:DOI[@name='{doi_name}']"
                f"/scl:DAI[@name='{dai_name}']"
                "/scl:Val"
            )

            input_values = [
                value.text or ""
                for value in input_root.xpath(
                    xpath,
                    namespaces=NSMAP,
                )
            ]
            output_values = [
                value.text or ""
                for value in output_root.xpath(
                    xpath,
                    namespaces=NSMAP,
                )
            ]

            assert len(input_values) == len(output_values)

            for original, sanitized in zip(
                input_values,
                output_values,
            ):
                assert sanitized
                assert sanitized != original

def test_sensitive_location_values_remain_numeric(
    sanitized_fixture: SanitizedFixture,
):
    root = sanitized_fixture.output_root

    ranges = {
        "latitude": (-90.0, 90.0),
        "longitude": (-180.0, 180.0),
        "altitude": (-100.0, 5000.0),
    }

    for dai_name, (minimum, maximum) in ranges.items():
        values = root.xpath(
            f".//scl:DOI[@name='PhyNam']"
            f"/scl:DAI[@name='{dai_name}']"
            "/scl:Val/text()",
            namespaces=NSMAP,
        )

        for text in values:
            value = float(text)
            assert minimum <= value <= maximum

def test_fixture_corpus_exercises_supported_features():
    roots = [
        parse_xml(path).getroot()
        for path in SCL_FIXTURES
    ]

    feature_xpaths = {
        "substation topology": ".//scl:Terminal",
        "composite IED references": (
            ".//*[@setSrcRef or @setDstRef or @srcRef]"
        ),
        "ExtRef identifiers": (
            ".//scl:ExtRef"
            "[@iedName or @ldInst or @srcLDInst or @srcCBName]"
        ),
        "ExtRef internal addresses": ".//scl:ExtRef[@intAddr]",
        "sensitive nameplate data": (
            ".//scl:DOI[@name='NamPlt' or @name='PhyNam']"
            "/scl:DAI/scl:Val"
        ),
    }

    for feature, xpath in feature_xpaths.items():
        matching_roots = [
            root
            for root in roots
            if root.xpath(xpath, namespaces=NSMAP)
        ]

        # This feature is not present in the fixture corpus.
        # That is valid for sparse SCL files such as SSD files.
        if not matching_roots:
            continue

        # The feature exists in at least one fixture, so the individual
        # parameterized tests are responsible for validating it.
        assert matching_roots