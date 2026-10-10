"""Decode a plaintext WNM Sleep Response Action body, without exposing keys.

Caller must remove MAC headers/protection and bind association evidence. Parsing
is not integrity validation, peer acceptance or proof of key installation.
"""


from wifiseclab.protocol.operating_classes import global_class_reference

def _tlvs(data):
    offset = 0
    while offset < len(data):
        if len(data) - offset < 2:
            raise ValueError("Truncated WNM element header")
        element_id, size = data[offset:offset + 2]
        end = offset + 2 + size
        if end > len(data):
            raise ValueError("WNM element exceeds enclosing field")
        yield element_id, data[offset + 2:end]
        offset = end


def decode_oci_element(element):
    """Decode exact OCI IE bytes, including optional complete OCT triplet."""
    if not isinstance(element, (bytes, bytearray)) or len(element) not in (6, 9):
        raise ValueError("Expected exact OCI element of 6 or 9 octets")
    if element[0] != 255 or element[1] != len(element) - 2 or element[2] != 54:
        raise ValueError("OCI element identity or length mismatch")
    result = dict(operating_class=element[3], primary_channel=element[4],
                  frequency_segment_1=element[5], oct_present=len(element) == 9,
                  channel_validation="unknown",
                  global_class_reference=global_class_reference(element[3]))
    if len(element) == 9:
        result["oct"] = dict(operating_class=element[6], primary_channel=element[7],
                             frequency_segment_1=element[8],
                             global_class_reference=global_class_reference(element[6]))
    return result


def decode_sleep_response(body):
    if not isinstance(body, (bytes, bytearray)) or not 11 <= len(body) <= 65535:
        raise ValueError("Expected bounded plaintext WNM Action body")
    if body[0] != 10 or body[1] != 17:
        raise ValueError("Not a WNM Sleep Mode Response")
    key_size = int.from_bytes(body[3:5], "little")
    key_end = 5 + key_size
    if key_end > len(body):
        raise ValueError("WNM Key Data exceeds body")
    keys = []
    for element_id, payload in _tlvs(body[5:key_end]):
        row = dict(subelement_id=element_id, length=len(payload), key_redacted=True)
        if element_id == 0:
            if len(payload) < 11:
                raise ValueError("Truncated WNM GTK subelement")
            key_length = payload[2]
            if not 5 <= key_length <= 32 or len(payload) != 11 + key_length:
                raise ValueError("WNM GTK key length mismatch")
            row.update(key_length=key_length,
                       rsc=int.from_bytes(payload[3:11], "little"))
        elif element_id in (1, 2):
            allowed = (24,) if element_id == 1 else (24, 40)
            if len(payload) not in allowed:
                raise ValueError("WNM integrity-key subelement length mismatch")
            row.update(key_id=int.from_bytes(payload[:2], "little"),
                       rsc=int.from_bytes(payload[2:8], "little"),
                       key_length=len(payload) - 8)
        else:
            row["unsupported"] = True
        keys.append(row)
    elements = list(_tlvs(body[key_end:]))
    if not elements or elements[0][0] != 93:
        raise ValueError("WNM Sleep Mode element must follow Key Data")
    sleeps = [payload for element_id, payload in elements if element_id == 93]
    if len(sleeps) != 1 or len(sleeps[0]) != 4:
        raise ValueError("Expected one WNM Sleep Mode element of length 4")
    ocis = [bytes((element_id, len(payload))) + bytes(payload)
            for element_id, payload in elements
            if element_id == 255 and payload and payload[0] == 54]
    if len(ocis) > 1:
        raise ValueError("Duplicate OCI elements are ambiguous")
    oci = decode_oci_element(ocis[0]) if ocis else None
    sleep = sleeps[0]
    return dict(dialog_token=body[2], action_type=sleep[0],
                response_status=sleep[1], key_data_length=key_size,
                sleep_interval=int.from_bytes(sleep[2:4], "little"),
                oci=oci,
                key_subelements=keys,
                trailing_element_metadata=[dict(element_id=i, length=len(v))
                                           for i, v in elements[1:]],
                integrity_validated=False, receiver_acceptance_confirmed=False)
