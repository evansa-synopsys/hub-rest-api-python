import argparse
import csv
import glob
import os
import shutil
import time

import pandas
from pandas.errors import EmptyDataError

from blackduck.HubRestApi import HubInstance

parser = argparse.ArgumentParser("A program to create reports for a given project-version and all of its subprojects")
parser.add_argument("project_name")
parser.add_argument("version_name")
parser.add_argument('-r', '--refresh', action='store_true',
                    help='delete existing reports in the results directory and regenerate')

args = parser.parse_args()
hub = HubInstance()

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
    except TypeError:
        return ["", ""]
    response = hub.execute_get(matchedFilesURL)
    if response.status_code == 200:
        matched_files = response.json()
    else:
        return ["", ""]
    result = []
    try:
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
        # print(bom_component['licenses'][0]['licenses'])
        license_url = bom_component['licenses'][0]['licenses'][0]['license']
        response = hub.execute_get(license_url)
    else:
        license_url = bom_component['licenses'][0]['license']
        response = hub.execute_get(license_url)
    if response.status_code == 200:
        license_details = response.json()
        result.append(license_details.get("name"))
        result.append(license_details.get("licenseFamily")["name"])
        return result
    else:
        return result


# search the list of vulnerable components for a matching component version url, return a list of vulnerabilities with
# remediation details for that bom component
def get_component_vuln_information(bom_component):
    global result
    response = hub.execute_get(
        "{}{}".format(bom_component['_meta']['links'][3].get('href'), hub.get_limit_paramstring(10000)))
    if response.status_code == 200:
        result = response.json().get('items')
    return result


# return a dictionary with remediation details from a call to /REMEDIATION endpoint
def build_component_remediation_data(vulnerable_components):
    remediation_data = dict()
    for info in vulnerable_components['items']:
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


def get_header():
    return ["Project Name", "Project Version", "Package Path", "Package Type", "Component Name",
            "Component Version Name",
            "Vulnerability Name", "Severity",
            "Base Score", "Remediation Status", "Vulnerability Published Date", "Vulnerability Updated Date",
            "Remediation Created At", "Fixed In", "Fix Available On", "Remediation Comment", "License Names",
            "License Family",
            "Download URL", "Component Description", "Latest Version Available", "Latest Version Release Date"]


def append_component_info(component, package_type, url_and_des, license_names_and_family, comp_version_url,
                          component_remediating_info, project_name, project_version):
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

    row.append(component['componentName'])
    row.append(component['componentVersionName'])

    component_row_list = []
    for i in range(10):
        row.append("")

    try:
        row.append(license_names_and_family[0])
        row.append(license_names_and_family[1])
    except IndexError as er:
        print("no license information found for:{} {} ".format(component['componentName'], er))
        row.append("", "")

    for ud in url_and_des:
        if not ud:
            row.append("")
        else:
            row.append(ud)

    try:
        row.append(component_remediating_info.get(comp_version_url)['latestAfterCurrent'].get('name'))
        row.append(
            clean_up_date(component_remediating_info.get(comp_version_url)['latestAfterCurrent'].get('releasedOn')))
    except (KeyError, TypeError):
        row.append(component['componentVersionName'])
        row.append(clean_up_date(component['releasedOn']))

    component_row_list.append(row.copy())

    return component_row_list


def append_vulnerabilities(package_type, component_vuln_information, row_list, row, license_names_and_family,
                           component_remediating_info, comp_version_url, url_and_des, component,
                           vuln_component_remediation_info, project_name, project_version):
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

    r.append(component['componentName'])
    r.append(component['componentVersionName'])

    for vuln in component_vuln_information:
        v_name_key = vuln['name']
        try:
            nvd_name = ""
            if v_name_key and vuln['_meta']['links'][1]:
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
        except (IndexError, TypeError):
            r.append(v_name_key)
        r.append(vuln['severity'])

        # prioritizes cvss3 over cvss2
        try:
            if vuln_component_remediation_info.get(v_name_key)['cvss3']:
                r.append(vuln_component_remediation_info.get(v_name_key)['cvss3'].get('baseScore'))
            elif vuln_component_remediation_info.get(v_name_key)['cvss2']:
                r.append(vuln_component_remediation_info.get(v_name_key)['cvss2'].get('baseScore'))
            else:
                r.append("")
        except (KeyError, TypeError):
            r.append("")

        try:
            r.append(vuln_component_remediation_info.get(v_name_key)['remediationStatus'])
        except (KeyError, TypeError):
            r.append("")

        r.append(clean_up_date(vuln['publishedDate']))
        r.append(clean_up_date(vuln['updatedDate']))

        try:
            r.append(clean_up_date(vuln_component_remediation_info.get(v_name_key)['createdAt']))
        except (KeyError, TypeError):
            r.append("")

        try:
            fixes_prev_vulnerabilities = \
            component_remediating_info.get(comp_version_url)['fixesPreviousVulnerabilities']['name']
            r.append(fixes_prev_vulnerabilities)
        except (KeyError, TypeError):
            r.append("")
            # print("Solution not available for - {}".format(v_name_key))

        try:
            fpv_released_on_date = clean_up_date(
                component_remediating_info.get(comp_version_url)['fixesPreviousVulnerabilities']['releasedOn'])
            r.append(fpv_released_on_date)
        except (KeyError, IndexError, TypeError):
            r.append("")
            # print("Solution Date not available for - {}".format(v_name_key))

        try:
            r.append(vuln_component_remediation_info.get(v_name_key)['comment'])
        except (KeyError, TypeError):
            r.append("")
            # print("No remediation comment for - {}".format(v_name_key))

        r.append(license_names_and_family[0])
        r.append(license_names_and_family[1])

        for ud in url_and_des:
            if not ud:
                r.append("")
            else:
                r.append(ud)

        try:
            r.append(component_remediating_info.get(comp_version_url)['latestAfterCurrent'].get('name'))
            r.append(
                clean_up_date(component_remediating_info.get(comp_version_url)['latestAfterCurrent'].get('releasedOn')))
        except (KeyError, TypeError):
            r.append(component['componentVersionName'])
            r.append(clean_up_date(component['releasedOn']))

        rl.append(r.copy())
        r = r[0:6]
    return rl


subprojects = list()


def generate_child_reports(component):
    child_project_name = component['componentName']
    child_project_version_name = component['componentVersionName']
    child_project_version = hub.get_project_version_by_name(child_project_name, child_project_version_name)
    child_project_components = hub.get_version_components(child_project_version, 100000)
    child_vulnerable_components = hub.get_vulnerable_bom_components(child_project_version)
    child_vuln_component_remediation_info = build_component_remediation_data(child_vulnerable_components)
    child_timestamp = time.strftime('%m_%d_%Y_%H_%M_%S')
    child_file_out = (projname + '_' + "subproject_src_report-" + child_timestamp)
    child_file_out = (child_file_out + ".csv")
    curdir = os.getcwd()
    os.chdir(curdir)
    with open(child_file_out, 'a', newline='') as f:
        first_child_file = True
        writer = csv.writer(f)
        for component in child_project_components['items']:
            package_type = getCompositePathContext(component)
            url_and_des = get_component_URL_and_description(component)
            license_names_and_family = get_license_names_and_family(component)
            component_vuln_information = get_component_vuln_information(component)
            comp_version_url = component.get('componentVersion')
            component_remediating_info = get_component_remediating_data(comp_version_url)
            row = []
            if first_child_file:
                header = get_header()
                writer.writerow(header)
                first_child_file = False

            row_list = []
            if len(component_vuln_information) <= 0:
                row_list = append_component_info(component, package_type, url_and_des, license_names_and_family,
                                                 comp_version_url, component_remediating_info, child_project_name,
                                                 child_project_version_name)
            elif len(component_vuln_information) > 0:
                row_list = append_vulnerabilities(package_type, component_vuln_information, row_list, row,
                                                  license_names_and_family,
                                                  component_remediating_info, comp_version_url, url_and_des, component,
                                                  child_vuln_component_remediation_info, child_project_name,
                                                  child_project_version_name)
            for row in row_list:
                writer.writerow(row)
    f.close()


def genreport():
    # build up the datasets
    projversion = hub.get_project_version_by_name(args.project_name, args.version_name)
    components = hub.get_version_components(projversion, 100000)
    vulnerable_components = hub.get_vulnerable_bom_components(projversion)
    vuln_component_remediation_info = build_component_remediation_data(vulnerable_components)
    project_name = args.project_name
    project_version = args.version_name
    curdir = os.getcwd()
    tempdir = os.path.join(curdir, 'temp')
    os.chdir(tempdir)
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
            component_vuln_information = get_component_vuln_information(component)
            comp_version_url = component.get('componentVersion')
            component_remediating_info = get_component_remediating_data(comp_version_url)
            row = []
            if first_file:
                header = get_header()
                writer.writerow(header)
                first_file = False
            row_list = []
            if len(component_vuln_information) <= 0:
                row_list = append_component_info(component, package_type, url_and_des, license_names_and_family,
                                                 comp_version_url, component_remediating_info, project_name,
                                                 project_version)
            elif len(component_vuln_information) > 0:
                row_list = append_vulnerabilities(package_type, component_vuln_information, row_list, row,
                                                  license_names_and_family,
                                                  component_remediating_info, comp_version_url, url_and_des, component,
                                                  vuln_component_remediation_info, project_name, project_version)

            for row in row_list:
                writer.writerow(row)
    f.close()


csv_list = []


def concat():
    curdir = os.getcwd()
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
    data_frame_concat.to_csv(file_out, index=False, quoting=1)
    shutil.move(file_out, '../results/')
    shutil.rmtree('../temp', ignore_errors=True)


def main():
    checkdirs()
    genreport()
    concat()


main()
