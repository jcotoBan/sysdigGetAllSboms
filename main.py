import yaml
import requests
import json

def get_base_url(region):
    region_urls = {
        "us1": "https://secure.sysdig.com/secure/vulnerability/",
        "us2": "https://us2.app.sysdig.com/secure/vulnerability/",
        "us4": "https://app.us4.sysdig.com/secure/vulnerability/",
        "eu1": "https://eu1.app.sysdig.com/secure/vulnerability/",
        "au1": "https://app.au1.sysdig.com/secure/vulnerability/",
        "me2": "https://app.me2.sysdig.com/secure/vulnerability/",
        "in1": "https://app.in1.sysdig.com/secure/vulnerability/"
    }
    return region_urls.get(region, region_urls["us1"])

# Load config
with open("config.yaml", "r") as f:
    config = yaml.safe_load(f)

api_token = config.get("api_token")
region = config.get("region", "us1")

if not api_token:
    raise ValueError("api_token not found in config.yaml")

base_url = get_base_url(region)
runtime_results_url = f"{base_url}v1/runtime-results"
sboms_url_template = f"{base_url}v1beta1/sboms?bomIdentifier={{}}"

headers = {
    "Authorization": f"Bearer {api_token}",
    "Content-Type": "application/json"
}

response = requests.get(runtime_results_url, headers=headers)
if response.status_code != 200:
    raise Exception(f"Failed to fetch runtime results: {response.status_code} {response.text}")

data = response.json()
sbom_ids = [entry["sbomId"] for entry in data.get("data", [])]

sbom_entries = []
for sbom_id in sbom_ids:
    sbom_url = sboms_url_template.format(sbom_id)
    sbom_response = requests.get(sbom_url, headers=headers)

    if sbom_response.status_code == 200:
        sbom_entries.append({
            "sbomId": sbom_id,
            "sbomData": sbom_response.json()
        })
    else:
        print(f"Warning: Failed to fetch SBOM for {sbom_id}: {sbom_response.status_code}")

with open("sboms.json", "w") as f:
    json.dump(sbom_entries, f, indent=2)

print("SBOM data saved to sboms.json")
