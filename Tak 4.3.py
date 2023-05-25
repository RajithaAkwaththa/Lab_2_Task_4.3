import matplotlib.pyplot as plt
import json
from os.path import join
def create_nvd_dict(year):
    filename = join("json", "nvdcve-1.1-" + str(year) + ".json")
    print("Opening: " + filename)
    with open(filename, encoding='utf8') as json_file:
        cve_dict = json.load(json_file)
    return cve_dict

def calculate_average_cvss(years, cps_component):
    cvss_scores = []

    for year in years:
        cve_dict = create_nvd_dict(year)
        CVE_Items = cve_dict['CVE_Items']

        for item in CVE_Items:
            if cps_component in item['configurations']['nodes'][0]['cpe_match'][0]['cpe23Uri']:
                try:
                    cvss_score = item['impact']['baseMetricV3']['cvssV3']['baseScore']
                    cvss_scores.append(float(cvss_score))
                except KeyError:
                    pass

    average_cvss = sum(cvss_scores) / len(cvss_scores)
    return average_cvss


# Define the years range
years = range(2002, 2021)

# Define the CPS component types
cps_components = ['RTU', 'PLC', 'HMI', 'MTU']

# Calculate the average CVSS scores for each CPS component type
average_cvss_scores = []
for cps_component in cps_components:
    average_cvss = calculate_average_cvss(years, cps_component)
    average_cvss_scores.append(average_cvss)

# Generate a bar chart for average CVSS scores
plt.bar(cps_components, average_cvss_scores)
plt.xlabel('CPS Component Types')
plt.ylabel('Average CVSS Score')
plt.title('Average CVSS Score by CPS Component Types')
plt.xticks(rotation=45)
plt.grid(True)
plt.show()
