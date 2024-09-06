import yaml
import requests
import click
import re
import logging
from oar.core.configstore import ConfigStore
from oar.cli.cmd_create_test_report import create_test_report

logger = logging.getLogger(__name__)


class ReleaseDetector:

    def __init__(self, minor_release):
        """
        Compare the latest z-stream version from file generated by ART and the latest stable version
        from release stream, if they're different, it means new z-stream release resources are
        prepared, we can kick off QE release flow
        """
        self._minor_release = minor_release

        # TODO: create statebox object

    def get_latest_zstream_version(self):
        """
        Get the latest z-stream version from file generated by ART
        """
        url = f"https://raw.githubusercontent.com/openshift/release-tests/z-stream/_releases/{self._minor_release}/{self._minor_release}.z.yaml"
        resp = requests.get(url)
        if resp.ok:
            yamlobj = yaml.safe_load(resp.text)
            # by default cannot get latest version with keys()[-1], need to sort the items with tuple
            releases = sorted(yamlobj["releases"].items(
            ), key=lambda item: tuple(map(int, item[0].split('.'))))
            if len(releases):
                return releases[-1][0]
            else:
                return None
        else:
            return None

    def get_latest_stable_version(self):
        """
        Get the latest stable version from release stream
        """
        url = f"https://amd64.ocp.releases.ci.openshift.org/api/v1/releasestream/4-stable/latest?prefix={self._minor_release}"
        resp = requests.get(url)
        if resp.ok:
            return resp.json()["name"]
        else:
            return None

    def compare_patch_versions(self, version_a, version_b):
        """
        Compare the patch version of OCP releases
        Input params are like version_a=4.15.6 version_b=4.15.7
        Return -1 if version a is less than version b
        Return 1 if version a is greater than version b
        Return 0 if version a equals version b
        """
        patch_version_a = int(version_a.split('.')[2])
        patch_version_b = int(version_b.split('.')[2])
        if patch_version_a < patch_version_b:
            return -1
        elif patch_version_a > patch_version_b:
            return 1
        else:
            return 0

    def start(self):
        """
        Entrypoint of cli cmd
        """
        latest_zstream_version = self.get_latest_zstream_version()
        latest_stable_version = self.get_latest_stable_version()

        logger.info(f"latest z-stream version: {latest_zstream_version}")
        logger.info(f"latest stable version: {latest_stable_version}")

        if latest_zstream_version is None or latest_stable_version is None:
            logger.error("get latest versions failed")
            return

        result = self.compare_patch_versions(
            latest_zstream_version, latest_stable_version)
        if result == 1:
            logger.info(
                f"new z-stream release is detected: {latest_zstream_version}")
            # TODO: init statebox
            create_test_report.invoke(click.Context(
                command=create_test_report, obj={"cs": ConfigStore(latest_zstream_version)}))
            logger.info(f"test report is created for {latest_zstream_version}")
        elif result == -1:
            logger.warning(
                f"latest z-stream version is less than latest stable version, it's abnormal. We need to contact ART")
        else:
            logger.info("no new z-stream release found")


def validate_minor_release(ctx, param, value):
    pattern = re.compile(r"^4\.\d{1,2}$")
    if not pattern.match(value):
        raise click.BadParameter(f"Invalid OCP minor version {value}")
    return value


@click.command()
@click.option("-r", "--minor-release",
              help="Minor release of OCP e.g. 4.y",
              prompt="Please input the minor version of OCP",
              required=True,
              callback=validate_minor_release)
def start_release_detector(minor_release):
    ReleaseDetector(minor_release).start()
