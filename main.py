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

# Pagination in case of more than 1000 records.

sbom_ids = []
limit = 1000
offset = 0
seen_ids = set()

print("Fetching runtime results with pagination...")

while True:
    paged_url = f"{runtime_results_url}?limit={limit}&offset={offset}"
    response = requests.get(paged_url, headers=headers)

    if response.status_code != 200:
        raise Exception(f"Failed to fetch runtime results: {response.status_code} {response.text}")

    page_data = response.json()
    data_entries = page_data.get("data", [])

    if not data_entries:
        break  # No more records

    new_ids = [entry["sbomId"] for entry in data_entries if entry["sbomId"] not in seen_ids]

    if not new_ids:
        print("No new IDs found in this page — stopping to avoid duplicates.")
        break

    sbom_ids.extend(new_ids)
    seen_ids.update(new_ids)

    print(f"Fetched {len(new_ids)} new entries (Total so far: {len(sbom_ids)})")

    if len(data_entries) < limit:
        break  # Last page reached

    offset += limit

#Individual sbom collections

sbom_entries = []

print(f"Fetching SBOMs for {len(sbom_ids)} IDs...")

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

# Save to file
with open("sboms.json", "w") as f:
    json.dump(sbom_entries, f, indent=2)

print(f"✅ SBOM data saved to sboms.json ({len(sbom_entries)} entries).")
