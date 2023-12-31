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
        logger.debug(f"Response status: {response.status_code}\n")
        try:
            from connectors.debug_utils.curl_script import make_curl
            make_curl(method, endpoint, headers=headers, params=params, data=data, verify_ssl=ms.verify_ssl)
        except Exception as err:
            logger.error(f"Error in curl utils: {str(err)}")

        if 200 <= response.status_code < 300:
            if response.text != "":
                return response.json()
            else:
                return True
        else:
            if response.text != "":
                err_resp = response.json()
                error_msg = 'Response [{0}:{1} Details: {2}]'.format(response.status_code, response.reason, err_resp)
            else:
                error_msg = 'Response [{0}:{1} Details: {2}]'.format(response.status_code, response.reason, response.content)
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


def get_comma_sep_values(data):
    if isinstance(data, list):
        return
    return data.split(",")


def update_match_conditions(new_cond, old_cond, **kwargs):
    if len(old_cond) < 1:
        return new_cond
    elif len(new_cond) < 1:
        return old_cond
    elif new_cond[0].get("operator") == old_cond[0].get("operator") == "IPMatch":
        new_match_value = new_cond[0].get("matchValue") or []
        old_match_value = old_cond[0].get("matchValue") or []
        new_negate_cond = new_cond[0].get("negateCondition")
        old_negate_cond = old_cond[0].get("negateCondition")
        negate_cond = None
        if new_negate_cond or new_negate_cond is False:
            negate_cond = new_negate_cond
        elif old_negate_cond or old_negate_cond is False:
            negate_cond = old_negate_cond
        if kwargs.get("remove_ips"):
            match_value = list(set(old_match_value) - set(new_match_value))
        else:
            match_value = list(set(old_match_value + new_match_value))
        match_conditions = {
            "operator": "IPMatch",
            "selector": new_cond[0].get("selector") or old_cond[0].get("selector"),
            "matchValue": match_value,
            "transforms": new_cond[0].get("transforms") or old_cond[0].get("transforms") or [],
            "matchVariable": new_cond[0].get("matchVariable") or old_cond[0].get("matchVariable"),
            "negateCondition": negate_cond
        }
        return [match_conditions]
    else:
        return new_cond or old_cond


def get_updated_custom_rules(old_custom_rule, new_custom_rule, **kwargs):
    if not old_custom_rule:
        return new_custom_rule
    elif old_custom_rule and not new_custom_rule:
        return old_custom_rule
    common_rules = set()
    rules = []

    for old_rule in old_custom_rule.get("rules", []):
        flag = True
        for new_rule in new_custom_rule.get("rules", []):
            if old_rule.get("name") == new_rule.get("name"):
                rule_dict = {
                    "name": new_rule.get("name"),
                    "enabledState": new_rule.get("enabledState") or old_rule.get("enabledState") or "Enabled",
                    "priority": new_rule.get("priority") or old_rule.get("priority"),
                    "ruleType": new_rule.get("ruleType") or old_rule.get("ruleType"),
                    "rateLimitDurationInMinutes": new_rule.get("rateLimitDurationInMinutes") or old_rule.get("rateLimitDurationInMinutes"),
                    "rateLimitThreshold": new_rule.get("rateLimitThreshold") or old_rule.get("rateLimitThreshold"),
                    "matchConditions": update_match_conditions(new_rule.get("matchConditions"), old_rule.get("matchConditions"), **kwargs),
                    "action": new_rule.get("action") or old_rule.get("action")
                }
                rules.append(rule_dict)
                common_rules.add(new_rule.get("name"))
                flag = False
                break
        flag and rules.append(old_rule)

    for new_rule in new_custom_rule.get("rules", []):
        if new_rule.get("name") not in common_rules:
            rules.append(new_rule)

    return {"rules": rules}


def get_request_data(params, policy, **kwargs):
    location = params.get("location") or policy.get("location")
    custom_rules_old = policy.get("properties", {}).get("customRules") or {}
    updated_custom_rules = get_updated_custom_rules(custom_rules_old, params.get("customRules") or {}, **kwargs)
    managed_rules = params.get("managedRules") or policy.get("properties", {}).get("managedRules")
    policy_settings = params.get("policySettings") or policy.get("properties", {}).get("policySettings")
    sku = params.get("sku") or policy.get("sku")
    if sku and not isinstance(sku, dict):
        sku = {"name": sku}
    tags = params.get("tags", {}) | policy.get("tags", {})
    properties = {}
    req_body = {}

    updated_custom_rules and properties.update({"customRules": updated_custom_rules})
    managed_rules and properties.update({"managedRules": managed_rules})
    policy_settings and properties.update({"policySettings": policy_settings})

    location and req_body.update({"location": location})
    properties and req_body.update({"properties": properties})
    sku and req_body.update({"sku": sku})
    tags and req_body.update({"tags": tags})
    return req_body


def create_or_update_policy(config, params, connector_info, **kwargs):
    policy = {}
    try:
        policy = get_policy_details(config, params, connector_info)
        logger.info("Existing policy found, updating the policy.")
    except Exception:
        logger.info("Policy not found, creating new policy.")
    req_body = get_request_data(params, policy, **kwargs)
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


def check_rule(policy, params):
    rule_found = False
    ip_rule = False
    old_rules = policy.get("properties", {}).get("customRules", {}).get("rules", [])
    for rule in old_rules:
        if rule.get("name") == params.get("rule_name"):
            rule_found = True
            match_conditions = rule.get("matchConditions", [])
            if len(match_conditions) > 0 and match_conditions[0].get("operator") == "IPMatch":
                ip_rule = True
                break
    if rule_found and not ip_rule:
        raise ConnectorError("Rule name already present with different Match Type.")
    return ip_rule


def block_ip(config, params, connector_info):
    policy = {}
    try:
        policy = get_policy_details(config, params, connector_info)
        logger.info("Existing policy found, updating the policy.")
    except Exception:
        logger.info("Policy not found, creating new policy.")

    if check_rule(policy, params):
        params.update({
            "customRules": {
                "rules": [
                    {
                        "name": params.get("rule_name"),
                        "priority": params.get("rule_priority"),
                        "matchConditions": [
                            {
                                "operator": "IPMatch",
                                "matchValue": get_comma_sep_values(params.get("ip_address") or [])
                            }
                        ],
                        "action": "Block"
                    }
                ]
            }
        })
    else:
        params.update({
            "customRules": {
                "rules": [
                    {
                        "name": params.get("rule_name"),
                        "enabledState": "Enabled",
                        "priority": params.get("rule_priority"),
                        "ruleType": "MatchRule",
                        "matchConditions": [
                            {
                                "matchVariable": "RemoteAddr",
                                "operator": "IPMatch",
                                "negateCondition": False,
                                "matchValue": get_comma_sep_values(params.get("ip_address") or [])
                            }
                        ],
                        "action": "Block"
                    }
                ]
            }
        })
    req_body = get_request_data(params, policy)
    endpoint = get_endpoint("create_or_update_policy", config, params)
    response = api_request("PUT", endpoint, connector_info, config, data=json.dumps(req_body))
    return response


def unblock_ip(config, params, connector_info):
    params.update({
        "customRules": {
            "rules": [
                {
                    "name": params.get("rule_name"),
                    "matchConditions": [
                        {
                            "operator": "IPMatch",
                            "matchValue": get_comma_sep_values(params.get("ip_address") or [])
                        }
                    ],
                    "action": "Block"
                }
            ]
        }
    })
    policy = {}
    try:
        policy = get_policy_details(config, params, connector_info)
    except Exception:
        raise ConnectorError('Policy not found')

    if not check_rule(policy, params):
        raise ConnectorError('Rule not found')
    req_body = get_request_data(params, policy, remove_ips=True)
    endpoint = get_endpoint("create_or_update_policy", config, params)
    response = api_request("PUT", endpoint, connector_info, config, data=json.dumps(req_body))
    return response


operations = {
    "create_or_update_policy": create_or_update_policy,
    "get_policy_details": get_policy_details,
    "get_policies_list": get_policies_list,
    "delete_policy": delete_policy,
    "block_ip": block_ip,
    "unblock_ip": unblock_ip
}
