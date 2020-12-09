import argparse
import csv
import glob
import logging
import os
import shutil
import re
import timeit
from urllib.error import HTTPError
import functools

import requests
import sys
import time

import pandas
from pandas.errors import EmptyDataError

from blackduck.HubRestApi import HubInstance

parser = argparse.ArgumentParser("A program to create reports for a given project-version and all of its subprojects")
parser.add_argument("project_name")
parser.add_argument("version_name")
parser.add_argument('-r', '--refresh', action='store_true',
                    help='delete existing reports in the results directory and regenerate')
parser.add_argument('-v', '--verbose', action='store_true', default=False, help='turn on DEBUG logging')

args = parser.parse_args()


def get_hub():
    global hub
    try:
        hub = HubInstance(refresh_token=True)
    except Exception as e:
        print("There was an exception thrown while creating the Hub instance object: {}".format(e))
        print("It is required that this script be executed in the same directory as .restconfig.json")
        print(".restconfig.json must contain an API token for authentication")
        return None
    else:
        return hub


hub = get_hub()

def set_logging_level(log_level):
    logging.basicConfig(stream=sys.stderr, level=log_level, format='%(asctime)s %(levelname)-8s %(message)s',datefmt='%Y-%m-%d %H:%M:%S')


if args.verbose:
    set_logging_level(logging.DEBUG)
else:
    set_logging_level(logging.INFO)

projname = args.project_name
timestamp = time.strftime('%m_%d_%Y_%H_%M')
file_out = (projname + '_' + "Consolidated_src_report-" + timestamp)
file_out = (file_out + ".csv")
rootDir = os.getcwd()


# print ("root dir=%s" % rootDir)

def doRefresh(dir_name):
    tempDir = os.path.join(rootDir, dir_name)
    print("tempDir=%s" % tempDir)
    for fileName in os.listdir(tempDir):
        print("Removing stale files %s" % fileName)
        os.remove(os.path.join(tempDir, fileName))


def checkdirs():
    os.chdir(rootDir)
    if not os.path.isdir('./temp'):
        os.makedirs('./temp')
        print('made temp directory')
    elif len(os.listdir('./temp')) != 0:
        doRefresh('temp')
    else:
        print('temp directory already exists')

    if not os.path.isdir('./results'):
        os.makedirs('./results')
        print('made results directory')
    elif args.refresh and len(os.listdir('./results')) != 0:
        print('refreshing results')
        doRefresh('results')
    else:
        print('results directory already exists')


def clean_up_date(date_string):
    return date_string.split('T')[0]


def getCompositePathContext(comp):
    try:
        matchedFilesURL = comp['_meta']['links'][4]['href']
    except TypeError as err:
        logging.debug("Error getting matched files for {}".format(comp['component']), err)
        return ["", ""]
    response = hub.execute_get(matchedFilesURL)
    if response.status_code == 200:
        matched_files = response.json()
    else:
        return ["", ""]
    result = []
    try:
        if len(matched_files['items']) <= 0 and comp['origins'][0]['externalId']:
            result.append(comp['origins'][0]['externalId'])
            result.append(comp['origins'][0]['externalNamespace'])
        else:
            result.append(matched_files['items'][0]['filePath']['path'])
            result.append(matched_files['items'][0]['filePath']['fileName'])
    except (TypeError, KeyError, IndexError):
        return ["", ""]
    return result


def get_component_URL_and_description(bomComponent):
    components_info = []
    component_url = bomComponent['component']
    response = hub.execute_get(component_url)
    if response.status_code == 200:
        component_details = response.json()
        components_info.append(component_details.get("url"))
        desc = component_details.get("description").strip().splitlines()
        components_info.append("".join(desc))
    return components_info


def get_license_names_and_family(bom_component):
    result = []
    if bom_component['licenses'][0]['licenses']:
        license_url = bom_component['licenses'][0]['licenses'][0]['license']
        response = hub.execute_get(license_url)
    else:
        license_url = bom_component['licenses'][0]['license']
        response = hub.execute_get(license_url)
    if response.status_code == 200:
        license_details = response.json()
        result.append(license_details.get("name"))
        result.append(license_details.get("licenseFamily")["name"] if license_details.get("licenseFamily") else "")
        return result
    else:
        return result


# search the list of vulnerable components for a matching component version url, return a list of vulnerabilities with
# remediation details for that bom component
def get_component_vuln_information(bom_component):
    result = []
    response = hub.execute_get(
        "{}{}".format(bom_component['_meta']['links'][3].get('href'), hub.get_limit_paramstring(10000)))
    if response.status_code in [200, 201]:
        result = response.json().get('items')
    else:
        response.raise_for_status()
    return result


def build_upgrade_guidance(components):
    guidance_dict = dict()
    components_with_origins = [comp for comp in components['items'] if comp.get('origins')]
    components_without_origins = [comp for comp in components['items'] if
                                  not comp.get('origins') and comp.get('componentVersion')]

    for cwoo in components_without_origins:
        r_key = cwoo.get('componentVersion')
        try:
            r_val = get_upgrade_guidance_version_name(cwoo.get('componentVersion'))
        except requests.exceptions.HTTPError as err:
            logging.debug("no upgrade guidance for:{}, with {}, writing an empty field ".format(r_key, err))
            r_val = ""
        r_dict = {r_key: r_val}
        guidance_dict.update(r_dict)

    for cwo in components_with_origins:
        ug_url = [guidance for guidance in cwo.get('origins')[0]['_meta']['links'] if
                  guidance['rel'] == "upgrade-guidance"]
        assert ug_url[0], "guidance url must exist"
        response = hub.execute_get(ug_url[0].get('href'))
        try:
            if response.status_code in [200, 201]:
                result_json = response.json()
                r_key = result_json['origin']
                r_val = result_json
                r_dict = {r_key: r_val}
                guidance_dict.update(r_dict)
                continue
            else:
                response.raise_for_status()
        except requests.exceptions.HTTPError as err:
            logging.debug("no upgrade guidance for:{}, with {}, writing an empty field ".format(r_key, err))
    return guidance_dict


# return a dictionary with remediation details from a call to /REMEDIATION endpoint
def build_component_remediation_data(vulnerable_components, componentName, componentVersion):
    remediation_data = dict()
    vc = [x for x in vulnerable_components['items'] if x.get('componentName') == componentName and x.get('componentVersionName') == componentVersion]
    for info in vc:
        response = hub.execute_get(info['_meta']['href'])
        if response.status_code == 200:
            rd = response.json()
            rkey = rd['id']
            rval = rd
            rdict = {rkey: rval}
            remediation_data.update(rdict)
            continue
    return remediation_data


# return a dictionary with the version url mapped to the latestAfterCurrent name and date
# after a call to the /REMEDIATING endpoint
def get_component_remediating_data(comp_version_name_url):
    remediating_data = dict()
    url = "{}{}".format(comp_version_name_url, "/remediating")
    response = hub.execute_get(url)
    if response.status_code == 200:
        rj = response.json()
        r_key = comp_version_name_url
        r_val = rj
        remediating_data.update({r_key: r_val})
    return remediating_data


def get_origin_url(comp):
    assert 'origins' in comp, "component must have an origins object"
    try:
        assert comp.get('origins')[0], "component must have an origin object"
    except IndexError:
        return comp.get('origins')
    assert 'origin' in comp.get('origins')[0]['origin'], "component must have an origin URL"
    return comp.get('origins')[0]['origin']


# get the short term target upgrade version
def get_upgrade_guidance_version_name(comp_version_url):
    url = "{}{}".format(comp_version_url, "/upgrade-guidance")
    resp = hub.execute_get(url)
    upgrade_target_version = ""
    if resp.status_code in [200, 201]:
        upgrade_target_version = resp.json()
    else:
        resp.raise_for_status()
        return upgrade_target_version
    return upgrade_target_version

def quote_versions(s):
    return "{}{}{}".format("\"",s, "\"")

def format_leading_zeros(n):
    match_re = '^0+[0-9]+\.*[0-9]*'
    if not re.match(match_re, str(n)):
        return n
    else:
        return "{}{}{}".format("=\"", n, "\"")


def get_header():
    return ["Project Name", "Project Version", "Package Path", "Package Type", "Component Name",
            "Component Version Name",
            "Vulnerability Name", "Severity",
            "Base Score", "Remediation Status", "Vulnerability Published Date", "Vulnerability Updated Date",
            "Remediation Created At", "Fixed In", "Remediation Comment", "License Names",
            "License Family",
            "Download URL", "Component Description", "Latest Version Available"]


def append_component_info(component, package_type, url_and_des, license_names_and_family, comp_version_url, project_name, project_version):
    name = component['componentName']
    version = component['componentVersionName']
    row = []
    if project_name:
        row.append(project_name)
    if project_version:
        row.append(project_version)
    if package_type is not None:
        row.append(package_type[0])
        row.append(package_type[1])
    else:
        row.append("")
        row.append("")

    row.append(name)
    row.append(quote_versions(version))

    component_row_list = []
    for i in range(9):
        row.append("")

    try:
        row.append(license_names_and_family[0])
        row.append(license_names_and_family[1])
    except IndexError as er:
        logging.debug("no license information found for:{} {}, writing empty values ".format(name, er))
        row.append("")
        row.append("")

    row.extend(add_url_and_desc(url_and_des))

    #latestAfterCurrent release is no longer available from the API.
    row.append(quote_versions(version))

    component_row_list.append(row.copy())

    return component_row_list


def append_vulnerabilities(package_type, component_vuln_information, row_list, row, license_names_and_family,
                           comp_version_url, url_and_des, component,
                           vulnerable_components, project_name, project_version, upgrade_guidance):

    name = component['componentName']
    version = component['componentVersionName']
    vuln_component_remediation_info = build_component_remediation_data(vulnerable_components, name, version)

    global comp_origin_url
    rl = row_list
    r = row

    if project_name:
        r.append(project_name)
    if project_version:
        r.append(project_version)

    if package_type is not None:
        row.append(package_type[0])
        row.append(package_type[1])
    else:
        row.append("")
        row.append("")

    r.append(name)
    r.append(quote_versions(version))

    diff = [x for x in vuln_component_remediation_info.keys() if x not in [y.get('name') for y in component_vuln_information]]
    for vuln in diff:
        r.append(vuln)
        r.extend(vcr_info(vuln, vuln_component_remediation_info))
        r.extend(add_short_term_upgrade_guidance(comp_version_url, component, upgrade_guidance))
        r.extend(add_rem_comment(vuln, vuln_component_remediation_info))
        r.extend(add_license_name_and_family(license_names_and_family))
        r.extend(add_url_and_desc(url_and_des))
        r.extend(add_long_term_upgrade_guidance(comp_version_url, component, upgrade_guidance))
        rl.append(r.copy())
        r = r[0:6]

    for vuln in component_vuln_information:
        v_name_key = vuln['name']
        try:
            nvd_name = ""
            related_vulnerabilities = [row for row in vuln['_meta']['links'] if
                                       row.get('rel') == "related-vulnerabilities"]
            if related_vulnerabilities[0].get('label') == "NVD":
                nvd = related_vulnerabilities[0]['href'].split('/')
                nvd_name = nvd[len(nvd) - 1]
            elif v_name_key and vuln['_meta']['links'][1]:
                nvd = vuln['_meta']['links'][1]['href'].split('/')
                nvd_name = nvd[len(nvd) - 1]
                if nvd_name == "default-remediation-status":
                    nvd_name = nvd[len(nvd) - 2]
            if vuln['source'] == "NVD":
                r.append(v_name_key)
            elif nvd_name.startswith("CWE"):
                r.append(v_name_key)
            else:
                r.append("{}({})".format(nvd_name, v_name_key))
        except (IndexError, TypeError, KeyError) as err:
            logging.debug("{} with err {}, using default {} instead".format("failed to get vulnerability record name "
                                                             "and source", err, v_name_key))
            r.append(v_name_key)

        r.extend(vcr_info(v_name_key, vuln_component_remediation_info))
        r.extend(add_short_term_upgrade_guidance(comp_version_url, component, upgrade_guidance))
        r.extend(add_rem_comment(v_name_key, vuln_component_remediation_info))
        r.extend(add_license_name_and_family(license_names_and_family))
        r.extend(add_url_and_desc(url_and_des))
        r.extend(add_long_term_upgrade_guidance(comp_version_url, component, upgrade_guidance))
        rl.append(r.copy())
        r = r[0:6]
    return rl


def add_license_name_and_family(license_names_and_family):
    result = []
    try:
        l_name = license_names_and_family[0]
        l_family = license_names_and_family[1]
    except(KeyError, IndexError, TypeError) as err:
        logging.debug("{} with err {}".format("Failed to get license name and family", err))
        result.append("")
        result.append("")
    else:
        result.append(l_name)
        result.append(l_family)
    return result


def add_url_and_desc(url_and_des):
    result = []
    for ud in url_and_des:
        result.append("" if not ud else ud)
    return result


def add_long_term_upgrade_guidance(comp_version_url, component, upgrade_guidance):
    global comp_origin_url
    result = []
    try:
        comp_origin_url = get_origin_url(component)
        assert comp_origin_url, "No origin url, use version url"
        upgrade_target = upgrade_guidance.get(comp_origin_url)['longTerm']['versionName']
    except AssertionError as err:
        try:
            upgrade_target = upgrade_guidance.get(comp_version_url)['longTerm']['versionName']
            assert upgrade_target, "No long term upgrade guidance found for {} , writing an empty value".format(
                comp_version_url)
            result.append(format_leading_zeros(upgrade_target))
        except AssertionError:
            result.append("")
    except (KeyError, TypeError) as err:
        logging.debug(
            "No upgrade guidance found for {}, with error {}, writing an empty value".format(comp_origin_url, err))
        result.append("")
    else:
        result.append(format_leading_zeros(upgrade_target))
    return result


def add_rem_comment(v_name_key, vuln_component_remediation_info):
    result = []
    try:
        rem_comment = vuln_component_remediation_info.get(v_name_key).get('comment')
    except (KeyError, TypeError, AttributeError) as err:
        logging.debug("No remediation comment available for {} with error {}".format(v_name_key, err))
        result.append("")
    else:
        result.append(rem_comment)
    return result


def add_short_term_upgrade_guidance(comp_version_url, component, upgrade_guidance):
    global comp_origin_url
    result = []
    try:
        comp_origin_url = get_origin_url(component)
        assert comp_origin_url, "No origin url, use version url"
        upgrade_target = upgrade_guidance.get(comp_origin_url)['shortTerm']['versionName']
    except AssertionError as err:
        try:
            upgrade_target = upgrade_guidance.get(comp_version_url)['shortTerm']['versionName']
            assert upgrade_target, "No short term upgrade guidance found for {} , writing an empty value".format(
                comp_version_url)
            result.append(format_leading_zeros(upgrade_target))
        except AssertionError:
            result.append("")
    except (KeyError, TypeError) as err:
        logging.debug(
            "No upgrade guidance found for {}, with error {}, writing an empty value".format(comp_origin_url, err))
        result.append("")
    else:
        result.append(format_leading_zeros(upgrade_target))
    return result


def vcr_info(v_name_key, vuln_component_remediation_info):
    result = []
    # prioritizes cvss3 over cvss2
    try:
        cvs_score = vuln_component_remediation_info.get(v_name_key)['cvss3'].get('baseScore')
        cvs_severity = vuln_component_remediation_info.get(v_name_key)['cvss3'].get('severity')
    except (KeyError, TypeError, AttributeError) as err:
        try:
            cvs_score = vuln_component_remediation_info.get(v_name_key)['cvss2'].get('baseScore')
            cvs_severity = vuln_component_remediation_info.get(v_name_key)['cvss2'].get('severity')
        except(KeyError, TypeError, AttributeError) as err:
            logging.debug(
                "{} with err {} for {}".format("No cvss2 or cvss3 score for vulnerability, writing empty value", err,
                                               v_name_key))
            result.append("")
            result.append("")
        else:
            result.append(cvs_severity)
            result.append(format_leading_zeros(cvs_score))
    else:
        result.append(cvs_severity)
        result.append(format_leading_zeros(cvs_score))

    try:
        rem_status = vuln_component_remediation_info.get(v_name_key).get('remediationStatus')
    except(KeyError, TypeError, AttributeError) as err:
        logging.debug(
            "{} with err {} for {}".format("failed to get remediationStatus for vulnerability, writing empty value",
                                           err, v_name_key))
        result.append("")
    else:
        result.append(rem_status)

    try:
        published_date = clean_up_date(vuln_component_remediation_info.get(v_name_key).get('publishedDate'))
        updated_date = clean_up_date(vuln_component_remediation_info.get(v_name_key).get('lastModifiedDate'))
    except(KeyError, TypeError, AttributeError) as err:
        logging.debug(
            "{} with err {} for {}".format("failed to get remediationStatus for vulnerability, writing empty value",
                                           err, v_name_key))
        result.append("")
        result.append("")
    else:
        result.append(published_date)
        result.append(updated_date)

    try:
        created_at = clean_up_date(vuln_component_remediation_info.get(v_name_key)['createdAt'])
    except (KeyError, TypeError, AttributeError) as err:
        logging.debug(
            "{} with err {} for {}".format("failed to get createdAt date for vulnerability, writing empty value", err,
                                           v_name_key))
        result.append("")
    else:
        result.append(created_at)
    return result


subprojects = list()


def generate_child_reports(component):
    child_project_name = component['componentName']
    child_project_version_name = component['componentVersionName']
    child_project_version = hub.get_project_version_by_name(child_project_name, child_project_version_name)
    child_project_components = hub.get_version_components(child_project_version, 10000)
    print("Component count returned for {} {} = {} ".format(child_project_name, child_project_version_name,
                                                            child_project_components['totalCount']))
    upgrade_guidance = build_upgrade_guidance(child_project_components)
    child_vulnerable_components = hub.get_vulnerable_bom_components(child_project_version)
    # child_vuln_component_remediation_info = build_component_remediation_data(child_vulnerable_components)
    child_timestamp = time.strftime('%m_%d_%Y_%H_%M_%S')
    child_file_out = (projname + '_' + "subproject_src_report-" + child_timestamp)
    child_file_out = (child_file_out + ".csv")
    curdir = os.getcwd()
    if not curdir.endswith("temp"):
        curdir = os.path.join(rootDir, "temp")
        os.chdir(curdir)
    with open(child_file_out, 'a', newline='') as f:
        first_child_file = True
        writer = csv.writer(f)
        for component in child_project_components['items']:
            package_type = getCompositePathContext(component)
            url_and_des = get_component_URL_and_description(component)
            license_names_and_family = get_license_names_and_family(component)
            comp_version_url = component.get('componentVersion')
            try:
                component_vuln_information = get_component_vuln_information(component)
            except requests.exceptions.HTTPError as err:
                component_vuln_information = []
                logging.debug(
                    "Http Error while getting component vulnerability info for: {} {}".format(comp_version_url, err))
            row = []
            if first_child_file:
                header = get_header()
                writer.writerow(header)
                first_child_file = False

            row_list = []
            if len(component_vuln_information) <= 0:
                row_list = append_component_info(component, package_type, url_and_des, license_names_and_family,
                                                 comp_version_url, child_project_name,
                                                 child_project_version_name)
            elif len(component_vuln_information) > 0:
                row_list = append_vulnerabilities(package_type, component_vuln_information, row_list, row,
                                                  license_names_and_family,
                                                  comp_version_url, url_and_des, component,
                                                  child_vulnerable_components, child_project_name,
                                                  child_project_version_name, upgrade_guidance)
            for row in row_list:
                writer.writerow(row)
    f.close()


def genreport():
    # build up the datasets
    projversion = hub.get_project_version_by_name(args.project_name, args.version_name)
    components = hub.get_version_components(projversion, 10000)
    print("Component count returned for {} {} = {} ".format(args.project_name, args.version_name,
                                                            components['totalCount']))
    upgrade_guidance = build_upgrade_guidance(components)
    vulnerable_components = hub.get_vulnerable_bom_components(projversion)
    # vuln_component_remediation_info = build_component_remediation_data(vulnerable_components)
    project_name = args.project_name
    project_version = args.version_name
    curdir = os.getcwd()
    if not curdir.endswith("temp"):
        curdir = os.path.join(rootDir, "temp")
        os.chdir(curdir)
    with open(file_out, 'w', newline='') as f:
        writer = csv.writer(f)
        first_file = True
        for component in components['items']:
            if len(component['activityData']) == 0:
                generate_child_reports(component)
                continue
            package_type = getCompositePathContext(component)
            url_and_des = get_component_URL_and_description(component)
            license_names_and_family = get_license_names_and_family(component)
            comp_version_url = component.get('componentVersion')
            try:
                component_vuln_information = get_component_vuln_information(component)
            except requests.exceptions.HTTPError as err:
                component_vuln_information = []
                logging.debug(
                    "Http Error while getting component vulnerability info for: {} {}".format(comp_version_url, err))
            row = []
            if first_file:
                header = get_header()
                writer.writerow(header)
                first_file = False
            row_list = []
            if len(component_vuln_information) <= 0:
                row_list = append_component_info(component, package_type, url_and_des, license_names_and_family,
                                                 comp_version_url, project_name,
                                                 project_version)
            elif len(component_vuln_information) > 0:
                row_list = append_vulnerabilities(package_type, component_vuln_information, row_list, row,
                                                  license_names_and_family,
                                                  comp_version_url, url_and_des, component,
                                                  vulnerable_components, project_name, project_version,
                                                  upgrade_guidance)

            for row in row_list:
                writer.writerow(row)
    f.close()


csv_list = []


def concat():
    curdir = os.getcwd()
    if not curdir.endswith("temp"):
        curdir = os.path.join(rootDir, "temp")
        os.chdir(curdir)
    all_csvs = glob.glob(os.path.join(curdir, '*.csv'))
    all_data_frames = []
    for csv in all_csvs:
        try:
            data_frame = pandas.read_csv(csv, index_col=None)
        except EmptyDataError:
            data_frame = pandas.DataFrame()

        all_data_frames.append(data_frame)
    data_frame_concat = pandas.concat(all_data_frames, axis=0, ignore_index=True)
    data_frame_concat.to_csv(file_out, index=False)
    shutil.move(file_out, '../results/')
    shutil.rmtree('../temp', ignore_errors=True)


def main():
    checkdirs()
    start = timeit.default_timer()
    print("Starting timer: {} seconds".format(int(timeit.default_timer())))
    genreport()
    print("Time spent generating consolidated report: {} seconds".format(int(timeit.default_timer() - start)))
    concat()


main()
