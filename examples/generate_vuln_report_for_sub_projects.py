import argparse
import csv
import glob
import os
import shutil
import time

import pandas

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
rootDir = os.path.dirname(os.path.realpath(__file__))


def doRefresh(dir_name):
    tempDir = os.path.join(rootDir, dir_name)
    print("tempDir=%s" % tempDir)
    for fileName in os.listdir(tempDir):
        print("Removing stale directory %s" % fileName)
        os.remove(os.path.join(tempDir, fileName))


def checkdirs():
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


def getCompositePathContext(comp):
    try:
        matchedFilesURL = comp['_meta']['links'][4]['href']
    except TypeError:
        return []
    response = hub.execute_get(matchedFilesURL)
    mfJson = None
    if response.status_code == 200:
        mfJson = response.json()
    result = []
    if mfJson['totalCount'] > 0:
        tempItems = mfJson['items']
        for index in range(len(tempItems)):
            result.append(tempItems[index]['filePath']['compositePathContext'])
        return result
    else:
        return []


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


def get_component_vuln_information(bom_component, vulnerable_components):
    vulnerable_bom_components_info = vulnerable_components['items']
    result = list()
    for info in vulnerable_bom_components_info:
        # print(info)
        if info['componentName'] == bom_component.get('componentName') and info[
            'componentVersionName'] == bom_component.get('componentVersionName'):
            result.append(info.get('vulnerabilityWithRemediation'))
            continue
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
    return ["Project Name", "Project Version", "Package Path and Type", "Component Name", "Component Version Name",
            "Vulnerability Name", "Severity",
            "Base Score", "Remediation Status", "Vulnerability Published Date", "Vulnerability Updated Date",
            "Remediation Created At", "Solution", "Solution Date", "Remediation Comment", "License Names",
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
        row.append(str(package_type))
    else:
        row.append("None")

    row.append(component['componentName'])
    row.append(component['componentVersionName'])

    component_row_list = []
    for i in range(10):
        row.append("None")

    row.append(license_names_and_family[0])
    row.append(license_names_and_family[1])

    for ud in url_and_des:
        if not ud:
            row.append("None")
        else:
            row.append(ud)

    try:
        row.append(component_remediating_info.get(comp_version_url)['latestAfterCurrent'].get('name'))
        row.append(component_remediating_info.get(comp_version_url)['latestAfterCurrent'].get('releasedOn'))
    except (KeyError, TypeError):
        row.append(component['componentVersionName'])
        row.append(component['releasedOn'])

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
        r.append(str(package_type))
    else:
        r.append("None")

    r.append(component['componentName'])
    r.append(component['componentVersionName'])

    for vuln in component_vuln_information:
        v_name_key = vuln['vulnerabilityName']
        r.append(v_name_key)
        r.append(vuln['severity'])
        r.append(vuln['baseScore'])
        r.append(vuln['remediationStatus'])
        r.append(vuln['vulnerabilityPublishedDate'])
        r.append(vuln['vulnerabilityUpdatedDate'])
        r.append(vuln['remediationCreatedAt'])

        try:
            v_solution = vuln_component_remediation_info.get(v_name_key)['solution'].strip().splitlines()
            r.append("".join(v_solution))
        except KeyError:
            r.append("None")
            # print("Solution not available for - {}".format(v_name_key))

        try:
            r.append(vuln_component_remediation_info.get(v_name_key)['solutionDate'])
        except KeyError:
            r.append("None")
            # print("Solution Date not available for - {}".format(v_name_key))

        try:
            r.append(vuln_component_remediation_info.get(v_name_key)['comment'])
        except KeyError:
            r.append("None")
            # print("No remediation comment for - {}".format(v_name_key))

        r.append(license_names_and_family[0])
        r.append(license_names_and_family[1])

        for ud in url_and_des:
            if not ud:
                r.append("None")
            else:
                r.append(ud)

        try:
            r.append(component_remediating_info.get(comp_version_url)['latestAfterCurrent'].get('name'))
            r.append(component_remediating_info.get(comp_version_url)['latestAfterCurrent'].get('releasedOn'))
        except (KeyError, TypeError):
            r.append(component['componentVersionName'])
            r.append(component['releasedOn'])

        rl.append(r.copy())
        r = r[0:5]
    return rl


subprojects = list()


def generate_child_reports(component):
    child_project_name = component['componentName']
    child_project_version_name = component['componentVersionName']
    child_project_version = hub.get_project_version_by_name(child_project_name, child_project_version_name)
    child_project_components = hub.get_version_components(child_project_version)
    child_vulnerable_components = hub.get_vulnerable_bom_components(child_project_version)
    child_vuln_component_remediation_info = build_component_remediation_data(child_vulnerable_components)
    child_timestamp = time.strftime('%m_%d_%Y_%H_%M')
    child_file_out = (projname + '_' + "subproject_src_report-" + child_timestamp)
    child_file_out = (child_file_out + ".csv")
    count = 0
    curdir = os.getcwd()
    os.chdir(curdir)
    f = open(child_file_out, 'a', newline='')
    writer = csv.writer(f)
    for component in child_project_components['items']:
        package_type = getCompositePathContext(component)
        url_and_des = get_component_URL_and_description(component)
        license_names_and_family = get_license_names_and_family(component)
        component_vuln_information = get_component_vuln_information(component, child_vulnerable_components)
        comp_version_url = component.get('componentVersion')
        component_remediating_info = get_component_remediating_data(comp_version_url)
        row = []
        if count == 0:
            header = get_header()
            writer.writerow(header)
            count += 1

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
    components = hub.get_version_components(projversion)
    vulnerable_components = hub.get_vulnerable_bom_components(projversion)
    vuln_component_remediation_info = build_component_remediation_data(vulnerable_components)
    project_name = args.project_name
    project_version = args.version_name
    curdir = os.getcwd()
    tempdir = os.path.join(curdir, 'temp')
    os.chdir(tempdir)
    f = open(file_out, 'w', newline='')
    writer = csv.writer(f)
    count = 0
    for component in components['items']:
        if len(component['activityData']) == 0:
            generate_child_reports(component)
            continue
        package_type = getCompositePathContext(component)
        url_and_des = get_component_URL_and_description(component)
        license_names_and_family = get_license_names_and_family(component)
        component_vuln_information = get_component_vuln_information(component, vulnerable_components)
        comp_version_url = component.get('componentVersion')
        component_remediating_info = get_component_remediating_data(comp_version_url)
        row = []
        if count == 0:
            header = get_header()
            writer.writerow(header)
            count += 1
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
    for csv in glob.glob('*.csv'):
        csv_list.append(csv)
    all_csvs = (pandas.read_csv(csv, sep=',') for csv in csv_list)
    consolidated = pandas.concat(all_csvs, ignore_index=True)
    consolidated.to_csv(file_out, index=False, encoding="utf-8")
    shutil.move(file_out, '../results/')
    shutil.rmtree('../temp', ignore_errors=True)


def main():
    checkdirs()
    genreport()
    concat()


main()
