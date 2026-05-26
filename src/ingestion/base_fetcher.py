import requests
from pathlib import Path


class BaseFetcher:

    def __init__(self, output_dir):

        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    def download_file(self, url, filename):

        print(f"[FETCHING] {url}")

        response = requests.get(url)

        if response.status_code == 200:

            filepath = self.output_dir / filename

            with open(filepath, "wb") as file:
                file.write(response.content)

            print(f"[SUCCESS] Saved to {filepath}")

            return filepath

        else:

            raise Exception(
                f"Failed downloading file: {response.status_code}"
            )
