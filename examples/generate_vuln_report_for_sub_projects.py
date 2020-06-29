from typing import Set, Any
import argparse
from blackduck.HubRestApi import HubInstance
import time
import shutil
import os
import glob
import pandas
import json
import csv

parser = argparse.ArgumentParser("A program to create reports for a given project-version and all of its subprojects")
parser.add_argument("project_name")
parser.add_argument("version_name")
parser.add_argument("-z", "--zip_file_name", default="reports.zip")
parser.add_argument('-r', '--refresh', action='store_true',
                    help='delete existing reports in the results directory and regenerate')

parser.add_argument('-t', '--tries', default=4, type=int,
                    help="How many times to retry downloading the report, i.e. wait for the report to be generated")
parser.add_argument('-s', '--sleep_time', default=5, type=int,
                    help="The amount of time to sleep in-between (re-)tries to download the report")

args = parser.parse_args()
hub = HubInstance()

# build up the datasets
projversion = hub.get_project_version_by_name(args.project_name, args.version_name)
components = hub.get_version_components(projversion)
vulnerable_components = hub.get_vulnerable_bom_components(projversion)

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
    if os.path.isdir('./temp') == False:
        os.makedirs('./temp')
        print('made temp directory')
    elif len(os.listdir('./temp')) != 0:
        doRefresh('temp')
    else:
        print('temp directory already exists')

    if os.path.isdir('./results') == False:
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
    component_details = None
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
        license_details = None
    if response.status_code == 200:
        license_details = response.json()
        result.append(license_details.get("name"))
        result.append(license_details.get("licenseFamily")["name"])
        return result
    else:
        return result


def get_component_vuln_information(bom_component):
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
def build_component_remediation_data():
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


vuln_component_remediation_info = build_component_remediation_data()


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
    return ["Package Path and Type", "Component Name", "Component Version Name", "Vulnerability Name", "Severity",
            "Base Score", "Remediation Status", "Vulnerability Published Date", "Vulnerability Updated Date",
            "Remediation Created At", "Solution", "Solution Date", "Remediation Comment", "License Names",
            "License Family",
            "Download URL", "Component Description", "Latest Version Available", "Latest Version Release Date"]


subprojects = list()


def generate_child_reports():
    child_timestamp = time.strftime('%m_%d_%Y_%H_%M')
    child_file_out = (projname + '_' + "subproject_src_report-" + child_timestamp)
    child_file_out = (child_file_out + ".csv")
    count = 0
    curdir = os.getcwd()
    os.chdir(curdir)
    f = open(child_file_out, 'a', newline='')
    writer = csv.writer(f)
    for component in subprojects:
        package_type = getCompositePathContext(component)
        url_and_des = get_component_URL_and_description(component)
        license_names_and_family = get_license_names_and_family(component)
        component_vuln_information = get_component_vuln_information(component)
        comp_version_url = component.get('componentVersion')
        component_remediating_info = get_component_remediating_data(comp_version_url)
        row = []
        if count == 0:
            header = get_header()
            writer.writerow(header)
            count += 1

        if package_type is not None:
            row.append(str(package_type))
        else:
            row.append("None")

        row.append(component['componentName'])
        row.append(component['componentVersionName'])

    row_list = []
    if len(component_vuln_information) <= 0:
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

        row_list.append(row.copy())

    elif len(component_vuln_information) > 0:
        for vuln in component_vuln_information:
            v_name_key = vuln['vulnerabilityName']
            row.append(v_name_key)
            row.append(vuln['severity'])
            row.append(vuln['baseScore'])
            row.append(vuln['remediationStatus'])
            row.append(vuln['vulnerabilityPublishedDate'])
            row.append(vuln['vulnerabilityUpdatedDate'])
            row.append(vuln['remediationCreatedAt'])

            try:
                v_solution = vuln_component_remediation_info.get(v_name_key)['solution'].strip().splitlines()
                row.append("".join(v_solution))
            except KeyError:
                row.append("None")
                # print("Solution not available for - {}".format(v_name_key))

            try:
                row.append(vuln_component_remediation_info.get(v_name_key)['solutionDate'])
            except KeyError:
                row.append("None")
                # print("Solution Date not available for - {}".format(v_name_key))

            try:
                row.append(vuln_component_remediation_info.get(v_name_key)['comment'])
            except KeyError:
                row.append("None")
                # print("No remediation comment for - {}".format(v_name_key))

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

            row_list.append(row.copy())
            row = row[0:3]

    for row in row_list:
        writer.writerow(row)
    f.close()


def genreport():
    count = 0
    curdir = os.getcwd()
    tempdir = os.path.join(curdir, 'temp')
    os.chdir(tempdir)
    f = open(file_out, 'a', newline='')
    writer = csv.writer(f)
    for component in components['items']:
        if len(component['activityData']) == 0:
            subprojects.append(component)
        package_type = getCompositePathContext(component)
        url_and_des = get_component_URL_and_description(component)
        license_names_and_family = get_license_names_and_family(component)
        component_vuln_information = get_component_vuln_information(component)
        comp_version_url = component.get('componentVersion')
        component_remediating_info = get_component_remediating_data(comp_version_url)
        row = []
        if count == 0:
            header = get_header()
            writer.writerow(header)
            count += 1

        if package_type is not None:
            row.append(str(package_type))
        else:
            row.append("None")

        row.append(component['componentName'])
        row.append(component['componentVersionName'])

        row_list = []
        if len(component_vuln_information) <= 0:
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

            row_list.append(row.copy())

        elif len(component_vuln_information) > 0:
            for vuln in component_vuln_information:
                v_name_key = vuln['vulnerabilityName']
                if v_name_key == "BDSA-2014-0001":
                    print(v_name_key)
                row.append(v_name_key)
                row.append(vuln['severity'])
                row.append(vuln['baseScore'])
                row.append(vuln['remediationStatus'])
                row.append(vuln['vulnerabilityPublishedDate'])
                row.append(vuln['vulnerabilityUpdatedDate'])
                row.append(vuln['remediationCreatedAt'])

                try:
                    v_solution = vuln_component_remediation_info.get(v_name_key)['solution'].strip().splitlines()
                    row.append("".join(v_solution))
                except KeyError:
                    row.append("None")
                    # print("Solution not available for - {}".format(v_name_key))

                try:
                    row.append(vuln_component_remediation_info.get(v_name_key)['solutionDate'])
                except KeyError:
                    row.append("None")
                    # print("Solution Date not available for - {}".format(v_name_key))

                try:
                    row.append(vuln_component_remediation_info.get(v_name_key)['comment'])
                except KeyError:
                    row.append("None")
                    # print("No remediation comment for - {}".format(v_name_key))

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

                row_list.append(row.copy())
                row = row[0:3]

        for row in row_list:
            writer.writerow(row)
    f.close()


csv_list = []


def concat():
    curdir = os.getcwd()
    os.chdir(curdir)
    for csv in glob.iglob('*.csv'):
        csv_list.append(csv)
    consolidated = pandas.concat([pandas.read_csv(csv) for csv in csv_list])
    consolidated.to_csv(file_out, index=False, encoding="utf-8")
    shutil.move(file_out, '../results/')
    shutil.rmtree('../temp', ignore_errors=True)


def main():
    checkdirs()
    genreport()
    generate_child_reports()
    concat()


main()
