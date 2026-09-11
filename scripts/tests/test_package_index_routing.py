"""The CI runner and its container build configure optional crate mirrors separately."""

import re
import unittest
from pathlib import Path


ROOT = Path(__file__).resolve().parents[2]
TEST_WORKFLOW = (ROOT / ".github/workflows/test.yml").read_text()
DOCKERIGNORE = (ROOT / ".dockerignore").read_text()

FORWARD = 'index_build_args=(--build-arg "CRATES_INDEX_URL=${CRATES_INDEX_URL}")'


class PackageIndexRoutingTests(unittest.TestCase):
    def test_every_image_build_forwards_the_address(self) -> None:
        """The daemon never sees the job environment.

        A build that forwards nothing still goes green -- cargo simply resolves
        from crates.io -- so an unrouted build is invisible in a log. The validation
        workflow builds the production Dockerfile and must hand the address
        over explicitly.
        """
        for name, workflow in (("test.yml", TEST_WORKFLOW),):
            with self.subTest(workflow=name):
                builds = [
                    line.strip()
                    for line in workflow.splitlines()
                    if "docker build" in line
                    and not line.strip().startswith("#")
                    and "--check" not in line
                ]
                self.assertTrue(builds, f"{name} builds no image")
                for build in builds:
                    # The probe deliberately drives its own array so it can
                    # point the address somewhere unreachable; what matters is
                    # that no build reaches the daemon with nothing attached.
                    self.assertRegex(build, r'\$\{(index|probe)_build_args\[@\]\}', build)
                self.assertIn(FORWARD, workflow)

    def test_the_forwarding_omits_a_name_that_holds_nothing(self) -> None:
        """An empty `--build-arg` is worse than none.

        It would pin a source naming an empty registry rather than leaving
        cargo on crates.io -- which is the fallback that keeps this image
        buildable away from the network the proxy lives on.
        """
        for workflow in (TEST_WORKFLOW,):
            self.assertIn('if [ -n "${CRATES_INDEX_URL:-}" ]; then', workflow)

    def test_the_image_context_carries_no_runner_written_cargo_config(self) -> None:
        """The runner and the image each write their own; only one is in scope.

        `test.yml` writes a source replacement into the checkout so its own
        cargo uses the proxy, then builds the image from that same checkout.
        Carried in, the Dockerfile appends a second `[source.crates-io]` and
        cargo refuses the duplicate key -- so the exclusion is what keeps the
        two mechanisms from colliding.
        """
        self.assertIn("\n.cargo/config.toml\n", DOCKERIGNORE)
        # Narrow on purpose: .cargo/ also holds committed configuration, and
        # excluding the directory would quietly drop that from the context too.
        self.assertNotIn("\n.cargo\n", DOCKERIGNORE)

    def test_the_runner_is_redirected_before_it_resolves_anything(self) -> None:
        """A config file written after the fetch redirects nothing."""
        for name, workflow in (("test.yml", TEST_WORKFLOW),):
            with self.subTest(workflow=name):
                proxy = workflow.index("- name: Point cargo at the crate proxy")
                first_cargo = next(
                    index
                    for index, line in enumerate(workflow.splitlines())
                    # Only commands that resolve dependencies count; `cargo
                    # --version` reads no registry and needs no redirect.
                    if re.match(
                        r"(run: )?cargo\s+(build|test|clippy|doc|fetch|check)\b",
                        line.strip(),
                    )
                    and "docker" not in line
                )
                proxy_line = workflow[:proxy].count("\n")
                self.assertLess(proxy_line, first_cargo)


if __name__ == "__main__":
    unittest.main()
