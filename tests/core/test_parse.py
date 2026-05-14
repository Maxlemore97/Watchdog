import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))

from watchdog_core.parsers import (  # noqa: E402
    Package,
    _extract_subshells,
    collect_packages as _collect_packages,
    parse_install,
    parse_packages,
)


class ParsePackagesTests(unittest.TestCase):
    def test_npm_install_plain(self):
        self.assertEqual(
            parse_packages("npm install lodash"),
            [Package("npm", "lodash", None)],
        )

    def test_npm_install_with_version(self):
        self.assertEqual(
            parse_packages("npm install lodash@4.17.20"),
            [Package("npm", "lodash", "4.17.20")],
        )

    def test_npm_short_alias_i(self):
        self.assertEqual(
            parse_packages("npm i lodash@4.17.20"),
            [Package("npm", "lodash", "4.17.20")],
        )

    def test_npm_scoped_no_version(self):
        self.assertEqual(
            parse_packages("npm install @scope/pkg"),
            [Package("npm", "@scope/pkg", None)],
        )

    def test_npm_scoped_with_version(self):
        self.assertEqual(
            parse_packages("npm install @scope/pkg@1.2.3"),
            [Package("npm", "@scope/pkg", "1.2.3")],
        )

    def test_npm_flags_are_skipped(self):
        self.assertEqual(
            parse_packages("npm install --save-dev typescript@5.0.0"),
            [Package("npm", "typescript", "5.0.0")],
        )

    def test_npm_multi_packages(self):
        self.assertEqual(
            parse_packages("npm install react react-dom@18.2.0"),
            [
                Package("npm", "react", None),
                Package("npm", "react-dom", "18.2.0"),
            ],
        )

    def test_pnpm_add(self):
        self.assertEqual(
            parse_packages("pnpm add lodash@4.17.21"),
            [Package("npm", "lodash", "4.17.21")],
        )

    def test_yarn_add(self):
        self.assertEqual(
            parse_packages("yarn add lodash"),
            [Package("npm", "lodash", None)],
        )

    def test_pip_install_eq(self):
        self.assertEqual(
            parse_packages("pip install requests==2.31.0"),
            [Package("PyPI", "requests", "2.31.0")],
        )

    def test_pip_install_range_strips_version(self):
        self.assertEqual(
            parse_packages("pip install 'requests>=2.0'"),
            [Package("PyPI", "requests", None)],
        )

    def test_pip3_multi(self):
        self.assertEqual(
            parse_packages("pip3 install requests==2.31.0 urllib3"),
            [
                Package("PyPI", "requests", "2.31.0"),
                Package("PyPI", "urllib3", None),
            ],
        )

    def test_cargo_add_with_version(self):
        self.assertEqual(
            parse_packages("cargo add serde@1.0.0"),
            [Package("crates.io", "serde", "1.0.0")],
        )

    def test_cargo_install_plain(self):
        self.assertEqual(
            parse_packages("cargo install ripgrep"),
            [Package("crates.io", "ripgrep", None)],
        )

    def test_gem_install(self):
        self.assertEqual(
            parse_packages("gem install rails"),
            [Package("RubyGems", "rails", None)],
        )

    def test_composer_require_with_version(self):
        self.assertEqual(
            parse_packages("composer require monolog/monolog:^2.0"),
            [Package("Packagist", "monolog/monolog", "^2.0")],
        )

    def test_composer_require_no_version(self):
        self.assertEqual(
            parse_packages("composer require monolog/monolog"),
            [Package("Packagist", "monolog/monolog", None)],
        )

    def test_unknown_manager(self):
        self.assertEqual(parse_packages("brew install wget"), [])

    def test_non_install_subcommand(self):
        self.assertEqual(parse_packages("npm run build"), [])

    def test_unrelated_command(self):
        self.assertEqual(parse_packages("ls -la /tmp"), [])

    def test_empty_command(self):
        self.assertEqual(parse_packages(""), [])

    def test_too_short(self):
        self.assertEqual(parse_packages("npm install"), [])

    def test_binary_with_path(self):
        self.assertEqual(
            parse_packages("/usr/local/bin/npm install lodash"),
            [Package("npm", "lodash", None)],
        )


class UvPipTests(unittest.TestCase):
    def test_uv_pip_install_single(self):
        self.assertEqual(
            parse_packages("uv pip install requests"),
            [Package("PyPI", "requests", None)],
        )

    def test_uv_pip_install_pinned(self):
        self.assertEqual(
            parse_packages("uv pip install requests==2.31.0"),
            [Package("PyPI", "requests", "2.31.0")],
        )

    def test_uv_pip_install_multi(self):
        self.assertEqual(
            parse_packages("uv pip install requests urllib3==2.0"),
            [
                Package("PyPI", "requests", None),
                Package("PyPI", "urllib3", "2.0"),
            ],
        )

    def test_uv_pip_install_skips_flag(self):
        self.assertEqual(
            parse_packages("uv pip install --index-url https://x requests"),
            [Package("PyPI", "requests", None)],
        )

    def test_uv_add_still_works(self):
        self.assertEqual(
            parse_packages("uv add httpx"),
            [Package("PyPI", "httpx", None)],
        )

    def test_uv_pip_not_install_subcmd(self):
        self.assertEqual(parse_packages("uv pip list"), [])


class UrlAndPathInstallTests(unittest.TestCase):
    def test_pip_local_archive(self):
        pkgs, notes = parse_install("pip install ./local-1.0.tar.gz")
        self.assertEqual(pkgs, [])
        self.assertTrue(any("url/path install" in n for n in notes))

    def test_pip_git_url(self):
        pkgs, notes = parse_install("pip install git+https://github.com/foo/bar")
        self.assertEqual(pkgs, [])
        self.assertTrue(any("url/path install" in n for n in notes))

    def test_pip_https_wheel(self):
        pkgs, notes = parse_install("pip install https://example.com/pkg-1.0.whl")
        self.assertEqual(pkgs, [])
        self.assertTrue(any("url/path install" in n for n in notes))

    def test_pip_absolute_path(self):
        pkgs, notes = parse_install("pip install /tmp/pkg-1.0.tar.gz")
        self.assertEqual(pkgs, [])
        self.assertTrue(any("url/path install" in n for n in notes))

    def test_pip_url_with_named_pkg(self):
        pkgs, notes = parse_install("pip install requests https://example.com/x.whl")
        self.assertEqual(pkgs, [Package("PyPI", "requests", None)])
        self.assertTrue(any("url/path install" in n for n in notes))

    def test_npm_tarball_path(self):
        pkgs, notes = parse_install("npm install ./vendor/foo.tgz")
        self.assertEqual(pkgs, [])
        self.assertTrue(any("url/path install" in n for n in notes))


class RequirementsFileTests(unittest.TestCase):
    def test_pip_dash_r(self):
        pkgs, notes = parse_install("pip install -r requirements.txt")
        self.assertEqual(pkgs, [])
        self.assertTrue(any("requirements file: requirements.txt" in n for n in notes))

    def test_pip_long_requirement(self):
        pkgs, notes = parse_install("pip install --requirement reqs.txt")
        self.assertEqual(pkgs, [])
        self.assertTrue(any("requirements file: reqs.txt" in n for n in notes))

    def test_pip_inline_equals_form(self):
        pkgs, notes = parse_install("pip install --requirement=reqs.txt")
        self.assertEqual(pkgs, [])
        self.assertTrue(any("requirements file: reqs.txt" in n for n in notes))

    def test_pip_editable(self):
        pkgs, notes = parse_install("pip install -e .")
        self.assertEqual(pkgs, [])
        self.assertTrue(any("editable install" in n for n in notes))

    def test_pip_constraint_file(self):
        pkgs, notes = parse_install("pip install -c constraints.txt requests")
        self.assertEqual(pkgs, [Package("PyPI", "requests", None)])
        self.assertTrue(any("constraints file: constraints.txt" in n for n in notes))

    def test_uv_pip_dash_r(self):
        pkgs, notes = parse_install("uv pip install -r requirements.txt")
        self.assertEqual(pkgs, [])
        self.assertTrue(any("requirements file: requirements.txt" in n for n in notes))


class SubshellTests(unittest.TestCase):
    def test_extract_bash_c(self):
        self.assertEqual(
            _extract_subshells("bash -c 'npm install evil'"),
            ["npm install evil"],
        )

    def test_extract_sh_c(self):
        self.assertEqual(
            _extract_subshells("sh -c \"pip install requests\""),
            ["pip install requests"],
        )

    def test_extract_zsh_c(self):
        self.assertEqual(
            _extract_subshells("zsh -c 'gem install rails'"),
            ["gem install rails"],
        )

    def test_extract_non_shell(self):
        self.assertEqual(_extract_subshells("npm install lodash"), [])

    def test_extract_no_dash_c(self):
        self.assertEqual(_extract_subshells("bash script.sh"), [])

    def test_collect_walks_subshell(self):
        pkgs, notes = _collect_packages(
            "bash -c 'npm install evil@1.0'",
            resolve_version_fn=lambda p: p,
        )
        self.assertEqual(pkgs, [Package("npm", "evil", "1.0")])
        self.assertEqual(notes, [])

    def test_collect_walks_chained_inside_subshell(self):
        pkgs, _ = _collect_packages(
            "bash -c 'npm install a && pip install b'",
            resolve_version_fn=lambda p: p,
        )
        self.assertEqual(
            sorted(pkgs, key=lambda p: p.name),
            [Package("npm", "a", None), Package("PyPI", "b", None)],
        )

    def test_quoted_operator_does_not_split(self):
        # The `;` inside the quoted echo argument must NOT split the
        # command into two segments. Only the top-level `&&` should.
        pkgs, _ = _collect_packages(
            "echo 'a;b' && npm install evil",
            resolve_version_fn=lambda p: p,
        )
        self.assertEqual(pkgs, [Package("npm", "evil", None)])

    def test_quoted_double_operator_does_not_split(self):
        pkgs, _ = _collect_packages(
            'echo "a && b" ; npm install evil',
            resolve_version_fn=lambda p: p,
        )
        self.assertEqual(pkgs, [Package("npm", "evil", None)])


class ParallelResolveTests(unittest.TestCase):
    """A8: collect_packages must run version resolution concurrently
    so multi-package installs don't stack registry latencies."""

    def test_calls_resolver_per_package(self):
        seen: list[str] = []

        def fake_resolve(p):
            seen.append(p.name)
            return p

        pkgs, _ = _collect_packages(
            "npm install a b c d",
            resolve_version_fn=fake_resolve,
        )
        self.assertEqual(sorted(p.name for p in pkgs), ["a", "b", "c", "d"])
        self.assertEqual(sorted(seen), ["a", "b", "c", "d"])

    def test_parallel_faster_than_serial(self):
        import time as _time

        def slow(p):
            _time.sleep(0.05)
            return p

        cmd = "pip install a b c d e f"  # 6 packages × 50ms = 300ms serial
        start = _time.monotonic()
        pkgs, _ = _collect_packages(cmd, resolve_version_fn=slow)
        elapsed = _time.monotonic() - start
        self.assertEqual(len(pkgs), 6)
        # Parallel with 8 workers should finish well under 300ms.
        self.assertLess(elapsed, 0.20)

    def test_single_package_does_not_use_pool(self):
        seen: list[str] = []

        def fake_resolve(p):
            seen.append(p.name)
            return p

        pkgs, _ = _collect_packages(
            "npm install onlyone",
            resolve_version_fn=fake_resolve,
        )
        self.assertEqual([p.name for p in pkgs], ["onlyone"])
        self.assertEqual(seen, ["onlyone"])


if __name__ == "__main__":
    unittest.main()