""" Copyright start
  Copyright (C) 2008 - 2023 Fortinet Inc.
  All rights reserved.
  FORTINET CONFIDENTIAL & FORTINET PROPRIETARY SOURCE CODE
  Copyright end """

import json

from requests import request, exceptions as req_exceptions
from .microsoft_api_auth import *
from connectors.core.connector import get_logger, ConnectorError

logger = get_logger("azure-front-door-waf")


def api_request(method, endpoint, connector_info, config, params={}, data={}, headers={}):
    try:
        ms = MicrosoftAuth(config)
        endpoint = ms.host + endpoint

        token = ms.validate_token(config, connector_info)
        headers["Authorization"] = token
        headers["Content-Type"] = "application/json"

        logger.debug(f"\n------------------req start-----------------\n{method} - {endpoint}\nparams - {params}\ndata - {data}")
        response = request(method, endpoint, headers=headers, params=params,
                           data=data, verify=ms.verify_ssl)
        try:
            from connectors.debug_utils.curl_script import make_curl
            make_curl(method, endpoint, headers=headers, params=params, data=data, verify_ssl=ms.verify_ssl)
        except Exception as err:
            logger.error(f"Error in curl utils: {str(err)}")

        if response.status_code in [200, 201, 204]:
            if response.text != "":
                return response.json()
            else:
                return True
        else:
            if response.text != "":
                err_resp = response.json()
                failure_msg = err_resp.get("error", {}).get("message") or err_resp.get("message")
                error_msg = 'Response [{0}:{1} Details: {2}]'.format(response.status_code, response.reason,
                                                                     failure_msg if failure_msg else '')
            else:
                error_msg = 'Response [{0}:{1}]'.format(response.status_code, response.reason)
            logger.error(error_msg)
            raise ConnectorError(error_msg)

    except req_exceptions.SSLError:
        logger.error('An SSL error occurred')
        raise ConnectorError('An SSL error occurred')
    except req_exceptions.ConnectionError:
        logger.error('A connection error occurred')
        raise ConnectorError('A connection error occurred')
    except req_exceptions.Timeout:
        logger.error('The request timed out')
        raise ConnectorError('The request timed out')
    except req_exceptions.RequestException:
        logger.error('There was an error while handling the request')
        raise ConnectorError('There was an error while handling the request')
    except Exception as err:
        raise ConnectorError(str(err))


def get_endpoint(function_name, config, params):
    subscription_id = config.get("subscription_id", "")
    resource_group_name = config.get("resource_group_name", "")
    api_version = config.get("api_version", "")
    policy_name = params.get("policyName", "")
    endpoint = ""
    if function_name in ("create_or_update_policy", "get_policy_details", "delete_policy"):
        endpoint = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.Network/FrontDoorWebApplicationFirewallPolicies/{policy_name}?api-version={api_version}"
    elif function_name == "get_policies_list":
        endpoint = f"/subscriptions/{subscription_id}/resourceGroups/{resource_group_name}/providers/Microsoft.Network/frontDoorWebApplicationFirewallPolicies?api-version={api_version}"
    return endpoint


def get_updated_custom_rules(old_custom_rule, new_custom_rule):
    if not old_custom_rule:
        return new_custom_rule
    elif old_custom_rule and not new_custom_rule:
        return old_custom_rule
    rule_name_match_value = {}

    for rule in old_custom_rule.get("rules", []):
        rule_name = rule.get("name")
        match_conditions = rule.get("matchConditions", [])
        if len(match_conditions) > 0:
            match_value = match_conditions[0].get("matchValue", [])
            operator = match_conditions[0].get("operator")
            if operator == "IPMatch" and rule_name:
                rule_name_match_value[rule_name] = match_value

    for rule in new_custom_rule.get("rules", []):
        rule_name = rule.get("name")
        match_conditions = rule.get("matchConditions", [])
        if len(match_conditions) > 0:
            match_value = match_conditions[0].get("matchValue", [])
            if rule_name in rule_name_match_value:
                old_match_value = rule_name_match_value[rule_name]
                li = list(set(old_match_value+match_value))
                match_conditions[0]["matchValue"] = li
    return new_custom_rule


def create_or_update_policy(config, params, connector_info):
    policy = {}
    try:
        policy = get_policy_details(config, params, connector_info)
        logger.info("Existing policy found, updating the policy.")
    except Exception:
        logger.info("Policy not found, creating new policy.")
        pass
    location = params.get("location") or policy.get("location")
    custom_rules_old = policy.get("properties", {}).get("customRules") or {}
    updated_custom_rules = get_updated_custom_rules(custom_rules_old, params.get("customRules") or {})
    managed_rules = params.get("managedRules") or policy.get("properties", {}).get("managedRules")
    policy_settings = params.get("policySettings") or policy.get("properties", {}).get("policySettings")
    sku = params.get("sku") or policy.get("sku")
    if sku and not isinstance(sku, dict):
        sku = {"name": sku}
    tags = params.get("tags") or policy.get("tags")
    properties = {}
    req_body = {}

    updated_custom_rules and properties.update({"customRules": updated_custom_rules})
    managed_rules and properties.update({"managedRules": managed_rules})
    policy_settings and properties.update({"policySettings": policy_settings})

    location and req_body.update({"location": location})
    properties and req_body.update({"properties": properties})
    sku and req_body.update({"sku": sku})
    tags and req_body.update({"tags": tags})

    endpoint = get_endpoint("create_or_update_policy", config, params)
    response = api_request("PUT", endpoint, connector_info, config, data=json.dumps(req_body))
    return response


def get_policy_details(config, params, connector_info):
    endpoint = get_endpoint("get_policy_details", config, params)
    response = api_request("GET", endpoint, connector_info, config)
    return response


def get_policies_list(config, params, connector_info):
    endpoint = get_endpoint("get_policies_list", config, params)
    response = api_request("GET", endpoint, connector_info, config)
    return response


def delete_policy(config, params, connector_info):
    endpoint = get_endpoint("delete_policy", config, params)
    response = api_request("DELETE", endpoint, connector_info, config)
    return {"success": "Deleted Successfully"}


operations = {
    "create_or_update_policy": create_or_update_policy,
    "get_policy_details": get_policy_details,
    "get_policies_list": get_policies_list,
    "delete_policy": delete_policy
}
