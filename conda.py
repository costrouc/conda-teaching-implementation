"""# Conda Teaching Implementation

Have you ever wondered how Conda works? I sure have! In the process I
have asked many core developers questions since I could not find
documentation.

"""

from typing import List, Dict, Callable, Set, Tuple
import ast
import bz2
import collections
import datetime
import hashlib
import json
import json
import os
import pathlib
import platform
import re
import re
import shutil
import shlex
import ssl
import sys
import struct
import tarfile
import urllib.request

PLATFORM_MAP = {
    'linux2': 'linux',
    'linux': 'linux',
    'darwin': 'osx',
    'win32': 'win',
    'zos': 'zos',
}

NON_X86_MACHINES = {
    'armv6l',
    'armv7l',
    'aarch64',
    'arm64',
    'ppc64',
    'ppc64le',
    's390x',
}


def platform_subdir():
    """Determine the subdir that corresponds to the given platform (os
    and architecture). The format is roughly
    "<platform>-<architecture>".

    """
    _platform = PLATFORM_MAP.get(sys.platform, "unknown")
    machine = platform.machine()
    if machine in NON_X86_MACHINES:
        return f"{_platform}-{machine}"
    elif _platform == "zos-z":
        return "zos-z"
    else:
        return f"{_platform}-{8 * struct.calcsize('P')}"


def repodata_identifiers(directory: pathlib.Path, channel_url: str, subdir: str):
    """Define a predictable mapping of url <-> repodata filename on the
    filesystem that is a function `f(directory, channel_url, subdir)` this
    allows for the repodata to be efficiently cached.

    """
    url = f"{channel_url}/{subdir}/repodata.json.bz2"
    url_hash = hashlib.sha256(url.encode('utf-8')).hexdigest()[:8]
    filename = directory / f"repodata-{subdir}-{url_hash}.json.bz2"
    return filename, url


def download_object_storage_file(url: str, filename: pathlib.Path, no_exist_ok: bool = False):
    headers = {}
    if filename.is_file():
        current_timezone = datetime.datetime.now(datetime.timezone.utc).astimezone().tzinfo
        last_modified = datetime.datetime.fromtimestamp(filename.lstat().st_mtime).replace(tzinfo=current_timezone).astimezone(datetime.timezone.utc)
        headers["If-Modified-Since"] = last_modified.strftime("%a, %d %b %Y %H:%M:%S GMT")

    ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    request = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(request, context=ssl_context) as response:
            with filename.open("wb") as f:
                shutil.copyfileobj(response, f)
    except urllib.error.HTTPError as e:
        if e.code != 304:
            raise e
        elif e.code == 404 and not no_exist_ok:
            raise ValueError(f'repodata for subdir with url={url} does not exist')


def download_repodata(directory: pathlib.Path, channel_url: str, subdir: str, no_exist_ok: bool = False) -> pathlib.Path:
    filename, url = repodata_identifiers(directory, channel_url, subdir)
    download_object_storage_file(url, filename, no_exist_ok)
    return filename


def download_channel(directory: pathlib.Path, channel_url: str, subdirs: List[str] = None, no_exist_ok: bool = False):
    subdirs = subdirs or ['noarch', platform_subdir()]
    for subdir in subdirs:
        download_repodata(directory, channel_url, subdir, no_exist_ok)


def load_repodata_packages(directory: pathlib.Path, channel_url: str, subdir: str):
    filename, _ = repodata_identifiers(directory, channel_url, subdir)
    with bz2.open(filename) as f:
        data = json.load(f)

    packages = collections.defaultdict(list)
    for value in data['packages'].values():
        packages[value['name']].append(value)
    return packages


def load_packages(directory: pathlib.Path, channel_url: str, subdirs: List[str] = None):
    subdirs = subdirs or ['noarch', platform_subdir()]

    packages = collections.defaultdict(list)
    for subdir in subdirs:
        subdir_packages = load_repodata_packages(directory, channel_url, subdir)
        for package_name, package_builds in subdir_packages.items():
            packages[package_name].extend(package_builds)
    return packages


def check_build_constraint(build_constraint: str, package: Dict):
    if build_constraint is None:
        return True

    return re.fullmatch(
        re.sub(r'\\\*', r'.*', re.escape(build_constraint)),
        package['build']) is not None


def check_version_compare_constraint(version_constraint: str, version: Tuple):
    def _reformat_star(match):
        return f"{match.group(1)}.*"
    version_constraint = re.sub('(\d)\*', _reformat_star, version_constraint)

    match = re.fullmatch(
       "(!=|~=|==|>=|<=|>|<)?([0-9*]+)(?:\.([0-9*]+))?(?:\.([0-9*]+)(?:[a-z].*)?)?",
        version_constraint
    )
    if match is None:
        print(version_constraint)
    compare, *cmp_version = match.groups()

    if cmp_version[1] is None:
        cmp_version[1] = cmp_version[2]
        cmp_version[2] = None

    if "*" in cmp_version:
        index = cmp_version.index("*")
        cmp_version = cmp_version[:index]
        version = version[:index]
    elif None in cmp_version:
        index = cmp_version.index(None)
        cmp_version = cmp_version[:index]
        version = version[:index]

    if None in version:
        index = version.index(None)
        cmp_version = cmp_version[:index]
        version = version[:index]

    version = tuple(map(int, version))
    cmp_version = tuple(map(int, cmp_version))

    if compare is None:
        return version == cmp_version
    elif compare == "==":
        return version == cmp_version
    elif compare == "~=":
        return version == cmp_version
    elif compare == "!=":
        return version != cmp_version
    elif compare == ">":
        return version > cmp_version
    elif compare == ">=":
        return version >= cmp_version
    elif compare == "<=":
        return version <= cmp_version
    elif compare == "<":
        return version < cmp_version


def check_version_or_constraint(version_constraint: str, version: Tuple):
    return any(
        check_version_compare_constraint(_, version)
        for _ in version_constraint.split('|'))


def check_version_and_constraint(version_constraint: str, version: Tuple):
    return all(
        check_version_or_constraint(_, version)
        for _ in version_constraint.split(','))


def check_version_constraint(version_constraint: str, package: Dict):
    if version_constraint is None:
        return True

    match = re.fullmatch(
       "(\d+)(?:\.(\d+)(?:\.(\d+).*)?)?",
       package['version'])
    major, minor, patch = match.groups()
    return check_version_and_constraint(version_constraint, [major, minor, patch])


def check_constraint(constraint: Tuple[str, str], package: Dict):
    version_constraint, build_constraint = constraint
    return check_version_constraint(version_constraint, package) and check_build_constraint(build_constraint, package)


def parse_package_spec(dependency: str):
    match = re.fullmatch('([^ ]+)(?: ([^ ]+))?(?: ([^ ]+))?', dependency)
    package_name, version_constraint, build_constraint = match.groups()
    return package_name, (version_constraint, build_constraint)


def select_package(available_packages: Dict[str, List], stack: List[Dict], package_name: str, initial_constraints: Dict[str, Set[str]], initial_package: Dict = None):
    iterator = iter(available_packages[package_name])
    if initial_package is not None:
        for package in iterator:
            if package == initial_package:
                break

    for package in available_packages[package_name]:
        _stack = stack + [package]
        if verify_constraints(_stack, initial_constraints):
            return package
    return None


def collect_constraints(stack: List[Dict], initial_constraints: Dict[str, Set[str]]) -> Dict[str, Set[Tuple[str, str]]]:
    constraints = collections.defaultdict(set)

    for package in stack:
        for depend in package['depends']:
            package_name, constraint = parse_package_spec(depend)
            constraints[package_name].add(constraint)

    for package_name in initial_constraints:
        constraints[package_name] |= initial_constraints[package_name]

    return constraints


def verify_constraints(stack: List[Dict], initial_constraints: Dict[str, Set[str]]):
    constraints = collect_constraints(stack, initial_constraints)
    for package in stack:
        for constraint in constraints[package['name']]:
            if not check_constraint(constraint, package):
                return False
    return True


def dummy_solve(available_packages: Dict[str, List], package_specs: List[str]):
    initial_constraints = collections.defaultdict(set)
    stack = []
    for package_spec in package_specs:
        package_name, constraint = parse_package_spec(package_spec)
        initial_constraints[package_name].add(constraint)
    _dummy_solve(available_packages, stack, initial_constraints)
    return stack


def _dummy_solve(available_packages: Dict[str, List], stack: List[Dict], initial_constraints: Dict[str, Set[str]]):
    constraints = collect_constraints(stack, initial_constraints)
    stack_package_names = {_['name'] for _ in stack}
    package_name = [_ for _ in constraints if _ not in stack_package_names][0]
    previous_package = None

    while True:
        package = select_package(available_packages, stack, package_name, initial_constraints, previous_package)
        if package is None:
            # when package is None it indicates that `select_package`
            # was not able to
            previous_package = stack.pop()
        else:
            previous_package = None
            stack.append(package)

        constraints = collect_constraints(stack, initial_constraints)
        stack_package_names = {_['name'] for _ in stack}

        if len(constraints.keys() - stack_package_names) == 0:
            # solve is complete since all constriaints are satisfied
            break
        if previous_package is None:
            package_name = [_ for _ in constraints if _ not in stack_package_names][0]
        else:
            package_name = previous_package['name']



def download_package(directory: pathlib.Path, url: str):
    filename = directory / url.split('/')[-1]
    ssl_context = ssl.SSLContext(ssl.PROTOCOL_SSLv23)
    with urllib.request.urlopen(url, context=ssl_context) as response:
        with filename.open("wb") as f:
            shutil.copyfileobj(response, f)


def extract_package(directory: pathlib.Path, url: str):
    filename = directory / url.split('/')[-1]
    extract_directory = filename.with_suffix('').with_suffix('')
    with tarfile.open(filename, mode='r:bz2') as tar:
        tar.extractall(extract_directory)


def download_packages(directory: str, packages: List[Dict], channel_url: str):
    for package in packages:
        url = f"{channel_url}/{package['subdir']}/{package['name']}-{package['version']}-{package['build']}.tar.bz2"
        download_package(directory, url)
        extract_package(directory, url)


def text_replace(data, placeholder, new_prefix):
    return data.replace(placeholder.encode('utf-8'), new_prefix.encode('utf-8'))


def binary_replace(data, placeholder, new_prefix):
    """Perform a binary replacement of `data`, where ``placeholder`` is
        replaced with ``new_prefix`` and the remaining string is padded with null
        characters.  All input arguments are expected to be bytes objects."""

    def replace(match):
        occurances = match.group().count(placeholder)
        padding = (len(placeholder) - len(new_prefix)) * occurances
        if padding < 0:
            raise ValueError("negative padding")
        return match.group().replace(placeholder, new_prefix) + b'\0' * padding

    pat = re.compile(re.escape(placeholder) + b'([^\0]*?)\0')
    return pat.sub(replace, data)


def update_prefix(placeholder: str, file_type: str, filename: pathlib.Path, install_directory: pathlib.Path):
    with filename.open("rb") as _f:
        data = _f.read()

    if file_type == "text":
        data = text_replace(data, placeholder, str(install_directory))
    elif file_type == "binary":
        data = binary_replace(data, placeholder.encode('utf-8'), str(install_directory).encode('utf-8'))

    with filename.open('wb') as _f:
        _f.write(data)


def fix_prefix(package_cache_directory: pathlib.Path, install_directory: pathlib.Path, package: Dict):
    package_directory = package_cache_directory / f"{package['name']}-{package['version']}-{package['build']}"
    prefix_filename = package_directory / "info" / "has_prefix"

    # no prefixes to fix if the file "<package-name>/info/has_prefix" does not exist
    if not prefix_filename.is_file():
       return

    with prefix_filename.open() as f:
        for line in f:
            tokens = [_.strip('"\'') for _ in shlex.split(line, posix=False)]
            placeholder, file_type, filename = tokens
            update_prefix(placeholder, file_type, package_directory / filename, install_directory)


def detect_python_version(packages: List[Dict]):
    for package in packages:
        if package['name'] == "python":
            return package['version']
    return None


def copy_package(package_cache_directory: pathlib.Path, install_directory: pathlib.Path, package: Dict):
    package_directory = package_cache_directory / f"{package['name']}-{package['version']}-{package['build']}"
    shutil.copytree(package_directory, install_directory, copy_function=os.link, dirs_exist_ok=True, ignore=shutil.ignore_patterns("info"))


def install_packages(package_cache_directory: pathlib.Path, install_directory: pathlib.Path, packages: List[Dict]):
    python_version = detect_python_version(packages)
    if python_version is not None:
        major_minor = '.'.join(python_version.split('.')[:2])
        noarch_python_directory = install_directory / "lib" / f"python{major_minor}"
        noarch_python_directory.mkdir(exist_ok=True, parents=True)

    for package in packages:
        package_install_directory = noarch_python_directory if package.get('noarch') == 'python' else install_directory
        # pre install
        copy_package(package_cache_directory, package_install_directory, package)
        fix_prefix(package_cache_directory, package_install_directory, package)
        # post install should happen here share/post-install/*
