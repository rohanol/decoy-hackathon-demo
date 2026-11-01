"""Fixed synthetic content. Every person, project and figure here is invented.

Names use example.com. No real organisation, service, credential or dataset.
"""

ORG = "DeceptionGraph Research Portal"

# Demo accounts: password values live in README.md (lab-only, DGLAB- prefix).
# Only a salted PBKDF2-SHA256 hash is kept in code.
ACCOUNTS = {
    "researcher@example.com": {
        "name": "Dr. Asha Verma",
        "role": "Research scientist",
        "salt": "1c598d0834f70e1c214579709c1138a4",
        "hash": "e9a533c610900f19759337a3bfa4cd17d1318aca37b92e4d0f451a59340406df",
    },
    "analyst@example.com": {
        "name": "Rahul Menon",
        "role": "Data analyst",
        "salt": "c66e09b6a34c6d13780929ed3f65d8e7",
        "hash": "fbed53c0e179d44fb069dfae86fcc5483894d4a7825c8fc2303fb6760fac19fa",
    },
}

ANNOUNCEMENTS = [
    {"date": "2026-10-28", "title": "Quarterly data-sharing review opens", "text": "Submit dataset access requests through your group lead by 15 November."},
    {"date": "2026-10-21", "title": "Workshop: reproducible sensor pipelines", "text": "A two-day internal workshop on calibration notebooks and versioned datasets."},
    {"date": "2026-10-09", "title": "Portal maintenance completed", "text": "Search now covers report abstracts and dataset descriptions."},
]

REPORTS = [
    {"slug": "coastal-sensor-calibration", "title": "Coastal sensor network calibration, 2026", "group": "Environmental Sensing",
     "date": "2026-09-30", "authors": "A. Verma, K. Iyer",
     "abstract": "Drift characterisation for forty synthetic tide and salinity sensors, with a recalibration schedule and uncertainty bounds.",
     "sections": ["Sensor inventory", "Drift model", "Recalibration schedule", "Open questions"]},
    {"slug": "campus-energy-baseline", "title": "Campus energy use baseline", "group": "Sustainable Systems",
     "date": "2026-08-14", "authors": "R. Menon, S. Rao",
     "abstract": "A baseline of building-level electricity use across a fictional campus, normalised for occupancy and weather.",
     "sections": ["Metering coverage", "Normalisation", "Baseline by building", "Next steps"]},
    {"slug": "language-corpus-survey", "title": "Regional language corpus survey", "group": "Language Technologies",
     "date": "2026-07-02", "authors": "M. Das, P. Nair",
     "abstract": "Coverage and licensing review of twelve synthetic text corpora considered for an internal translation pilot.",
     "sections": ["Corpora reviewed", "Licensing", "Coverage gaps", "Recommendation"]},
    {"slug": "lab-equipment-utilisation", "title": "Shared lab equipment utilisation", "group": "Facilities",
     "date": "2026-06-11", "authors": "J. Thomas",
     "abstract": "Booking and usage patterns for shared microscopes and spectrometers over two synthetic quarters.",
     "sections": ["Booking data", "Utilisation", "Bottlenecks", "Proposals"]},
]

DATASETS = [
    {"id": "DS-1042", "title": "Synthetic tide gauge readings (hourly)", "rows": "87,600", "access": "Internal", "owner": "Environmental Sensing"},
    {"id": "DS-1077", "title": "Fictional building meter export", "rows": "12,480", "access": "Internal", "owner": "Sustainable Systems"},
    {"id": "DS-1103", "title": "Corpus metadata catalogue", "rows": "1,206", "access": "Restricted", "owner": "Language Technologies"},
    {"id": "DS-1118", "title": "Equipment booking log (anonymised)", "rows": "4,915", "access": "Internal", "owner": "Facilities"},
]

TASKS = [
    {"title": "Review drift model assumptions", "due": "2026-11-06", "status": "In progress"},
    {"title": "Share baseline notebook with group", "due": "2026-11-10", "status": "Not started"},
    {"title": "Update dataset DS-1042 description", "due": "2026-11-14", "status": "Not started"},
]


def search(query: str):
    q = query.strip().lower()
    if not q:
        return []
    hits = []
    for report in REPORTS:
        if q in report["title"].lower() or q in report["abstract"].lower() or q in report["group"].lower():
            hits.append({"kind": "Report", "title": report["title"], "href": f"/reports/{report['slug']}", "text": report["abstract"]})
    for dataset in DATASETS:
        if q in dataset["title"].lower() or q in dataset["owner"].lower() or q in dataset["id"].lower():
            hits.append({"kind": "Dataset", "title": f"{dataset['id']} · {dataset['title']}", "href": "/resources", "text": f"{dataset['rows']} rows · {dataset['owner']}"})
    return hits
