from __future__ import annotations

import schemathesis


def test_openapi_contracts(app_instance) -> None:
    schema = schemathesis.from_asgi("/openapi.json", app=app_instance)
    for operation in schema.get_all_operations():
        if operation.method.upper() == "POST" and operation.path == "/messages":
            case = operation.make_case(body={"message": "Contract test message"})
        else:
            case = operation.make_case()
        response = case.call_asgi()
        case.validate_response(response)
