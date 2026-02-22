"""Tests for the TR-069 ACS server tool.

These tests verify SOAP building, parsing, session management and action
execution without requiring network access or a real CPE device.
"""

import unittest
import xml.etree.ElementTree as ET
from unittest.mock import MagicMock, patch

from tools.tr069_server import (
    ALL_KNOWN_PARAMS,
    CERT_PARAMS,
    CREDENTIAL_PARAMS,
    DEVICE_INFO_PARAMS,
    DNS_PARAMS,
    GPON_PARAMS,
    MGMT_SERVER_PARAMS,
    NS_CWMP,
    NS_SOAP_ENV,
    TELNET_SSH_PARAMS,
    WAN_PARAMS,
    WEB_USER_PARAMS,
    WIFI_PARAMS,
    ActionExecutor,
    CWMPMethod,
    CWMPSession,
    DeviceInfo,
    RPCResult,
    SOAPBuilder,
    SOAPParser,
    SessionManager,
)

# ---------------------------------------------------------------------------
# Sample SOAP envelopes used across multiple tests
# ---------------------------------------------------------------------------

SAMPLE_INFORM = '''<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
  <SOAP-ENV:Header>
    <cwmp:ID SOAP-ENV:mustUnderstand="1">1234</cwmp:ID>
  </SOAP-ENV:Header>
  <SOAP-ENV:Body>
    <cwmp:Inform>
      <DeviceId>
        <Manufacturer>Huawei</Manufacturer>
        <OUI>00E0FC</OUI>
        <ProductClass>HG8145V5</ProductClass>
        <SerialNumber>48575443C1234567</SerialNumber>
      </DeviceId>
      <Event><EventStruct><EventCode>0 BOOTSTRAP</EventCode></EventStruct></Event>
      <ParameterList>
        <ParameterValueStruct>
          <Name>InternetGatewayDevice.DeviceInfo.SoftwareVersion</Name>
          <Value>V5R020C10S115</Value>
        </ParameterValueStruct>
      </ParameterList>
    </cwmp:Inform>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>'''

SAMPLE_GPV_RESPONSE = '''<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
  <SOAP-ENV:Header>
    <cwmp:ID SOAP-ENV:mustUnderstand="1">42</cwmp:ID>
  </SOAP-ENV:Header>
  <SOAP-ENV:Body>
    <cwmp:GetParameterValuesResponse>
      <ParameterList>
        <ParameterValueStruct>
          <Name>InternetGatewayDevice.DeviceInfo.Manufacturer</Name>
          <Value>Huawei</Value>
        </ParameterValueStruct>
        <ParameterValueStruct>
          <Name>InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID</Name>
          <Value>MyWiFi</Value>
        </ParameterValueStruct>
      </ParameterList>
    </cwmp:GetParameterValuesResponse>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>'''

SAMPLE_SPV_RESPONSE = '''<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
  <SOAP-ENV:Header>
    <cwmp:ID SOAP-ENV:mustUnderstand="1">55</cwmp:ID>
  </SOAP-ENV:Header>
  <SOAP-ENV:Body>
    <cwmp:SetParameterValuesResponse>
      <Status>0</Status>
    </cwmp:SetParameterValuesResponse>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>'''

SAMPLE_FAULT_RESPONSE = '''<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
  <SOAP-ENV:Header>
    <cwmp:ID SOAP-ENV:mustUnderstand="1">99</cwmp:ID>
  </SOAP-ENV:Header>
  <SOAP-ENV:Body>
    <SOAP-ENV:Fault>
      <FaultCode>9002</FaultCode>
      <FaultString>Internal error</FaultString>
    </SOAP-ENV:Fault>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>'''

SAMPLE_REBOOT_RESPONSE = '''<?xml version="1.0" encoding="UTF-8"?>
<SOAP-ENV:Envelope xmlns:SOAP-ENV="http://schemas.xmlsoap.org/soap/envelope/" xmlns:cwmp="urn:dslforum-org:cwmp-1-0">
  <SOAP-ENV:Header>
    <cwmp:ID SOAP-ENV:mustUnderstand="1">77</cwmp:ID>
  </SOAP-ENV:Header>
  <SOAP-ENV:Body>
    <cwmp:RebootResponse>
      <Status>1</Status>
    </cwmp:RebootResponse>
  </SOAP-ENV:Body>
</SOAP-ENV:Envelope>'''


# ===================================================================
# SOAPBuilder tests
# ===================================================================

class TestSOAPBuilder(unittest.TestCase):
    """Test SOAP envelope generation for every RPC method."""

    def _parse(self, xml_str: str) -> ET.Element:
        return ET.fromstring(xml_str.strip())

    def _body_local_name(self, xml_str: str) -> str:
        """Return the local tag name of the first child of <Body>."""
        root = self._parse(xml_str)
        for elem in root.iter():
            tag = elem.tag
            local = tag.rsplit("}", 1)[-1] if "}" in tag else tag
            if local == "Body":
                for child in elem:
                    child_local = child.tag.rsplit("}", 1)[-1] if "}" in child.tag else child.tag
                    return child_local
        return ""

    # -- InformResponse ---------------------------------------------------

    def test_inform_response_structure(self):
        xml, rid = SOAPBuilder.inform_response(request_id="IR-1")
        self.assertEqual(rid, "IR-1")
        self.assertIn("InformResponse", xml)
        self.assertIn("MaxEnvelopes", xml)
        root = self._parse(xml)
        self.assertIsNotNone(root)

    def test_inform_response_auto_id(self):
        xml, rid = SOAPBuilder.inform_response()
        self.assertTrue(rid)  # auto-generated id is non-empty
        self.assertIn(rid, xml)

    # -- GetParameterValues -----------------------------------------------

    def test_gpv_contains_parameter_names(self):
        params = ["InternetGatewayDevice.DeviceInfo.Manufacturer",
                   "InternetGatewayDevice.DeviceInfo.SerialNumber"]
        xml, rid = SOAPBuilder.get_parameter_values(params, request_id="GPV-1")
        self.assertEqual(rid, "GPV-1")
        self.assertIn("GetParameterValues", xml)
        for p in params:
            self.assertIn(p, xml)
        self.assertIn(f'arrayType="xsd:string[{len(params)}]"', xml)

    # -- SetParameterValues -----------------------------------------------

    def test_spv_contains_values(self):
        params = {
            "InternetGatewayDevice.X_HW_CLITelnetAccess.Enable": ("true", "xsd:boolean"),
        }
        xml, rid = SOAPBuilder.set_parameter_values(params, request_id="SPV-1")
        self.assertEqual(rid, "SPV-1")
        self.assertIn("SetParameterValues", xml)
        self.assertIn("X_HW_CLITelnetAccess.Enable", xml)
        self.assertIn("true", xml)
        self.assertIn("xsd:boolean", xml)

    def test_spv_parameter_key(self):
        params = {"A.B": ("1", "xsd:string")}
        xml, _ = SOAPBuilder.set_parameter_values(params, parameter_key="PK-1")
        self.assertIn("<ParameterKey>PK-1</ParameterKey>", xml)

    # -- GetParameterNames ------------------------------------------------

    def test_gpn_next_level_flag(self):
        xml, _ = SOAPBuilder.get_parameter_names(
            "InternetGatewayDevice.", next_level=True, request_id="GPN-1"
        )
        self.assertIn("GetParameterNames", xml)
        self.assertIn("<NextLevel>1</NextLevel>", xml)

    def test_gpn_no_next_level(self):
        xml, _ = SOAPBuilder.get_parameter_names(
            "InternetGatewayDevice.", next_level=False
        )
        self.assertIn("<NextLevel>0</NextLevel>", xml)

    # -- Download ---------------------------------------------------------

    def test_download_envelope(self):
        xml, rid = SOAPBuilder.download(
            file_type="1 Firmware Upgrade Image",
            url="http://acs.example.com/firmware.bin",
            file_size=1024,
            request_id="DL-1",
        )
        self.assertEqual(rid, "DL-1")
        self.assertIn("Download", xml)
        self.assertIn("1 Firmware Upgrade Image", xml)
        self.assertIn("http://acs.example.com/firmware.bin", xml)
        self.assertIn("<FileSize>1024</FileSize>", xml)

    # -- Reboot -----------------------------------------------------------

    def test_reboot_envelope(self):
        xml, rid = SOAPBuilder.reboot(request_id="RB-1")
        self.assertEqual(rid, "RB-1")
        self.assertIn("Reboot", xml)
        self.assertIn("CommandKey", xml)

    # -- FactoryReset -----------------------------------------------------

    def test_factory_reset_envelope(self):
        xml, rid = SOAPBuilder.factory_reset(request_id="FR-1")
        self.assertEqual(rid, "FR-1")
        self.assertIn("FactoryReset", xml)

    # -- AddObject --------------------------------------------------------

    def test_add_object_envelope(self):
        xml, rid = SOAPBuilder.add_object(
            "InternetGatewayDevice.LANDevice.1.",
            parameter_key="AO-KEY",
            request_id="AO-1",
        )
        self.assertIn("AddObject", xml)
        self.assertIn("InternetGatewayDevice.LANDevice.1.", xml)
        self.assertIn("AO-KEY", xml)

    # -- DeleteObject -----------------------------------------------------

    def test_delete_object_envelope(self):
        xml, rid = SOAPBuilder.delete_object(
            "InternetGatewayDevice.LANDevice.1.Host.2.",
            request_id="DO-1",
        )
        self.assertIn("DeleteObject", xml)
        self.assertIn("InternetGatewayDevice.LANDevice.1.Host.2.", xml)

    # -- Envelope structure -----------------------------------------------

    def test_envelope_has_soap_namespaces(self):
        xml, _ = SOAPBuilder.reboot(request_id="NS-1")
        root = self._parse(xml)
        # Verify the envelope can be parsed and has a Header and Body
        tag = root.tag
        local = tag.rsplit("}", 1)[-1] if "}" in tag else tag
        self.assertEqual(local, "Envelope")


# ===================================================================
# SOAPParser tests
# ===================================================================

class TestSOAPParser(unittest.TestCase):
    """Test parsing of CWMP SOAP messages."""

    def test_detect_inform(self):
        method = SOAPParser.detect_method(SAMPLE_INFORM.encode())
        self.assertEqual(method, CWMPMethod.INFORM)

    def test_detect_gpv_response(self):
        method = SOAPParser.detect_method(SAMPLE_GPV_RESPONSE.encode())
        self.assertEqual(method, CWMPMethod.GET_PARAMETER_VALUES_RESPONSE)

    def test_detect_spv_response(self):
        method = SOAPParser.detect_method(SAMPLE_SPV_RESPONSE.encode())
        self.assertEqual(method, CWMPMethod.SET_PARAMETER_VALUES_RESPONSE)

    def test_detect_fault(self):
        method = SOAPParser.detect_method(SAMPLE_FAULT_RESPONSE.encode())
        self.assertEqual(method, CWMPMethod.FAULT)

    def test_detect_empty_for_garbage(self):
        method = SOAPParser.detect_method(b"not xml at all")
        self.assertEqual(method, CWMPMethod.EMPTY)

    def test_parse_request_id(self):
        rid = SOAPParser.parse_request_id(SAMPLE_INFORM.encode())
        self.assertEqual(rid, "1234")

    def test_parse_request_id_missing(self):
        rid = SOAPParser.parse_request_id(b"<root/>")
        self.assertEqual(rid, "")

    # -- Inform parsing ---------------------------------------------------

    def test_parse_inform_device_id(self):
        device = SOAPParser.parse_inform(SAMPLE_INFORM.encode())
        self.assertEqual(device.manufacturer, "Huawei")
        self.assertEqual(device.oui, "00E0FC")
        self.assertEqual(device.product_class, "HG8145V5")
        self.assertEqual(device.serial_number, "48575443C1234567")

    def test_parse_inform_events(self):
        device = SOAPParser.parse_inform(SAMPLE_INFORM.encode())
        self.assertIn("0 BOOTSTRAP", device.events)

    def test_parse_inform_parameters(self):
        device = SOAPParser.parse_inform(SAMPLE_INFORM.encode())
        self.assertEqual(
            device.parameters.get(
                "InternetGatewayDevice.DeviceInfo.SoftwareVersion"
            ),
            "V5R020C10S115",
        )
        self.assertEqual(device.software_version, "V5R020C10S115")

    def test_parse_inform_bad_xml(self):
        device = SOAPParser.parse_inform(b"<<<not valid xml>>>")
        self.assertEqual(device.manufacturer, "")

    # -- GPV response parsing ---------------------------------------------

    def test_parse_gpv_response_parameters(self):
        result = SOAPParser.parse_get_parameter_values_response(
            SAMPLE_GPV_RESPONSE.encode()
        )
        self.assertTrue(result.success)
        self.assertEqual(
            result.parameters["InternetGatewayDevice.DeviceInfo.Manufacturer"],
            "Huawei",
        )
        self.assertEqual(
            result.parameters[
                "InternetGatewayDevice.LANDevice.1.WLANConfiguration.1.SSID"
            ],
            "MyWiFi",
        )

    def test_parse_gpv_response_request_id(self):
        result = SOAPParser.parse_get_parameter_values_response(
            SAMPLE_GPV_RESPONSE.encode()
        )
        self.assertEqual(result.request_id, "42")

    # -- SPV response parsing ---------------------------------------------

    def test_parse_spv_response_success(self):
        result = SOAPParser.parse_set_parameter_values_response(
            SAMPLE_SPV_RESPONSE.encode()
        )
        self.assertTrue(result.success)
        self.assertEqual(result.status, 0)

    # -- Fault parsing ----------------------------------------------------

    def test_parse_gpv_with_fault(self):
        result = SOAPParser.parse_get_parameter_values_response(
            SAMPLE_FAULT_RESPONSE.encode()
        )
        self.assertFalse(result.success)
        self.assertEqual(result.fault_code, "9002")
        self.assertEqual(result.fault_string, "Internal error")

    # -- Simple response parsing ------------------------------------------

    def test_parse_reboot_response(self):
        result = SOAPParser.parse_simple_response(
            "RebootResponse", SAMPLE_REBOOT_RESPONSE.encode()
        )
        self.assertTrue(result.success)
        self.assertEqual(result.status, 1)
        self.assertEqual(result.request_id, "77")

    def test_parse_simple_response_bad_xml(self):
        result = SOAPParser.parse_simple_response("Reboot", b"not xml")
        self.assertFalse(result.success)
        self.assertIn("XML parse error", result.fault_string)


# ===================================================================
# SessionManager tests
# ===================================================================

class TestSessionManager(unittest.TestCase):
    """Test CWMP session lifecycle."""

    def setUp(self):
        self.mgr = SessionManager()

    def test_create_session(self):
        session = self.mgr.create_session()
        self.assertIsInstance(session, CWMPSession)
        self.assertTrue(session.session_id.startswith("ACS-"))

    def test_get_session(self):
        session = self.mgr.create_session()
        retrieved = self.mgr.get_session(session.session_id)
        self.assertIs(session, retrieved)

    def test_get_session_not_found(self):
        self.assertIsNone(self.mgr.get_session("nonexistent"))

    def test_remove_session(self):
        session = self.mgr.create_session()
        self.mgr.remove_session(session.session_id)
        self.assertIsNone(self.mgr.get_session(session.session_id))

    def test_list_sessions(self):
        s1 = self.mgr.create_session()
        s2 = self.mgr.create_session()
        sessions = self.mgr.list_sessions()
        self.assertEqual(len(sessions), 2)

    def test_get_or_create_new_session(self):
        session, is_new = self.mgr.get_or_create("")
        self.assertTrue(is_new)
        self.assertIsNotNone(session)

    def test_get_or_create_existing_session(self):
        session = self.mgr.create_session()
        cookie = f"CWMP_SESSIONID={session.session_id}"
        retrieved, is_new = self.mgr.get_or_create(cookie)
        self.assertFalse(is_new)
        self.assertEqual(retrieved.session_id, session.session_id)

    def test_rpc_queue_management(self):
        session = self.mgr.create_session()
        session.rpc_queue.append(("GetParameterValues", ["A.B"]))
        session.rpc_queue.append(("Reboot", None))
        self.assertEqual(len(session.rpc_queue), 2)
        item = session.rpc_queue.pop(0)
        self.assertEqual(item[0], "GetParameterValues")
        self.assertEqual(len(session.rpc_queue), 1)


# ===================================================================
# ActionExecutor tests
# ===================================================================

class TestActionExecutor(unittest.TestCase):
    """Test that each action queues the correct RPCs."""

    def setUp(self):
        self.executor = ActionExecutor("0.0.0.0", 7547)

    def test_dump_config_queues_gpv(self):
        queue = self.executor.build_rpc_queue("dump-config")
        self.assertEqual(len(queue), 1)
        method, params = queue[0]
        self.assertEqual(method, "GetParameterValues")
        self.assertEqual(params, ALL_KNOWN_PARAMS)

    def test_enable_telnet_queues_spv(self):
        queue = self.executor.build_rpc_queue("enable-telnet")
        self.assertEqual(len(queue), 1)
        method, params = queue[0]
        self.assertEqual(method, "SetParameterValues")
        self.assertIn("InternetGatewayDevice.X_HW_CLITelnetAccess.Enable", params)
        self.assertEqual(params["InternetGatewayDevice.X_HW_CLITelnetAccess.Enable"],
                         ("true", "xsd:boolean"))

    def test_enable_ssh_queues_spv(self):
        queue = self.executor.build_rpc_queue("enable-ssh")
        self.assertEqual(len(queue), 1)
        method, params = queue[0]
        self.assertEqual(method, "SetParameterValues")
        self.assertIn("InternetGatewayDevice.X_HW_CLISSHAccess.Enable", params)

    def test_extract_creds_queues_gpv(self):
        queue = self.executor.build_rpc_queue("extract-creds")
        self.assertEqual(len(queue), 1)
        method, params = queue[0]
        self.assertEqual(method, "GetParameterValues")
        self.assertEqual(params, CREDENTIAL_PARAMS)

    def test_extract_certs_queues_gpv(self):
        queue = self.executor.build_rpc_queue("extract-certs")
        method, params = queue[0]
        self.assertEqual(method, "GetParameterValues")
        self.assertEqual(params, CERT_PARAMS)

    def test_extract_wifi_queues_gpv(self):
        queue = self.executor.build_rpc_queue("extract-wifi")
        method, params = queue[0]
        self.assertEqual(method, "GetParameterValues")
        self.assertEqual(params, WIFI_PARAMS)

    def test_extract_gpon_queues_gpv(self):
        queue = self.executor.build_rpc_queue("extract-gpon")
        method, params = queue[0]
        self.assertEqual(method, "GetParameterValues")
        self.assertEqual(params, GPON_PARAMS)

    @patch("tools.tr069_server.ActionExecutor._get_local_ip", return_value="192.168.100.50")
    def test_change_acs_queues_spv(self, _mock_ip):
        queue = self.executor.build_rpc_queue("change-acs")
        method, params = queue[0]
        self.assertEqual(method, "SetParameterValues")
        self.assertIn("InternetGatewayDevice.ManagementServer.URL", params)
        url_value = params["InternetGatewayDevice.ManagementServer.URL"][0]
        self.assertIn("192.168.100.50", url_value)

    def test_change_dns_queues_spv(self):
        queue = self.executor.build_rpc_queue("change-dns")
        method, params = queue[0]
        self.assertEqual(method, "SetParameterValues")
        key = "InternetGatewayDevice.LANDevice.1.LANHostConfigManagement.DNSServers"
        self.assertIn(key, params)
        self.assertIn("1.1.1.1", params[key][0])

    def test_reboot_queues_reboot(self):
        queue = self.executor.build_rpc_queue("reboot")
        self.assertEqual(queue, [("Reboot", None)])

    def test_factory_reset_queues_factory_reset(self):
        queue = self.executor.build_rpc_queue("factory-reset")
        self.assertEqual(queue, [("FactoryReset", None)])

    def test_open_wan_mgmt_queues_spv(self):
        queue = self.executor.build_rpc_queue("open-wan-mgmt")
        method, params = queue[0]
        self.assertEqual(method, "SetParameterValues")
        self.assertIn("InternetGatewayDevice.X_HW_CLITelnetAccess.Enable", params)
        self.assertIn("InternetGatewayDevice.X_HW_CLISSHAccess.Enable", params)

    def test_unknown_action_returns_empty(self):
        queue = self.executor.build_rpc_queue("nonexistent-action")
        self.assertEqual(queue, [])


# ===================================================================
# DeviceInfo dataclass tests
# ===================================================================

class TestDeviceInfo(unittest.TestCase):
    """Test DeviceInfo dataclass creation."""

    def test_default_values(self):
        info = DeviceInfo()
        self.assertEqual(info.manufacturer, "")
        self.assertEqual(info.events, [])
        self.assertEqual(info.parameters, {})

    def test_from_inform(self):
        info = SOAPParser.parse_inform(SAMPLE_INFORM.encode())
        self.assertIsInstance(info, DeviceInfo)
        self.assertEqual(info.manufacturer, "Huawei")
        self.assertEqual(info.product_class, "HG8145V5")
        self.assertTrue(info.raw_xml)


# ===================================================================
# CWMP constants tests
# ===================================================================

class TestCWMPConstants(unittest.TestCase):
    """Verify parameter path constants are defined correctly."""

    def test_device_info_params_not_empty(self):
        self.assertGreater(len(DEVICE_INFO_PARAMS), 0)
        for p in DEVICE_INFO_PARAMS:
            self.assertTrue(p.startswith("InternetGatewayDevice.DeviceInfo."))

    def test_mgmt_server_params(self):
        self.assertGreater(len(MGMT_SERVER_PARAMS), 0)
        for p in MGMT_SERVER_PARAMS:
            self.assertTrue(p.startswith("InternetGatewayDevice.ManagementServer."))

    def test_wifi_params(self):
        self.assertGreater(len(WIFI_PARAMS), 0)
        self.assertTrue(any("SSID" in p for p in WIFI_PARAMS))
        self.assertTrue(any("PreSharedKey" in p for p in WIFI_PARAMS))

    def test_telnet_ssh_params(self):
        self.assertTrue(any("Telnet" in p for p in TELNET_SSH_PARAMS))
        self.assertTrue(any("SSH" in p for p in TELNET_SSH_PARAMS))

    def test_gpon_params(self):
        self.assertTrue(any("PLOAM" in p for p in GPON_PARAMS))

    def test_all_known_params_contains_subsets(self):
        for p in DEVICE_INFO_PARAMS:
            self.assertIn(p, ALL_KNOWN_PARAMS)
        for p in WIFI_PARAMS:
            self.assertIn(p, ALL_KNOWN_PARAMS)

    def test_credential_params_aggregation(self):
        for p in WEB_USER_PARAMS:
            self.assertIn(p, CREDENTIAL_PARAMS)
        for p in WAN_PARAMS:
            self.assertIn(p, CREDENTIAL_PARAMS)


if __name__ == "__main__":
    unittest.main()
