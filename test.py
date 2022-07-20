import tempfile
import pathlib

import conda

channel_url = "https://conda.anaconda.org/conda-forge"
directory = pathlib.Path(tempfile.gettempdir())
package_cache_directory = directory / "cache"
install_directory = directory / "install_directory"
packages = [
    "python >=3.8,<3.9",
    "flask",
]

package_cache_directory.mkdir(exist_ok=True)

conda.download_channel(directory, channel_url)
available_packages = conda.load_packages(directory, channel_url)
selected_packages = conda.dummy_solve(available_packages, packages)
conda.download_packages(package_cache_directory, selected_packages, channel_url)
conda.install_packages(package_cache_directory, install_directory, selected_packages)
