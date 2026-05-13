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
    split_name_version,
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


class SplitNameVersionTests(unittest.TestCase):
    def test_npm_simple(self):
        self.assertEqual(split_name_version("lodash@4.17.20", "npm"), ("lodash", "4.17.20"))

    def test_npm_scoped(self):
        self.assertEqual(split_name_version("@scope/pkg@1.0.0", "npm"), ("@scope/pkg", "1.0.0"))

    def test_npm_scoped_no_version(self):
        self.assertEqual(split_name_version("@scope/pkg", "npm"), ("@scope/pkg", None))

    def test_pip_eq(self):
        self.assertEqual(split_name_version("requests==2.0", "pip"), ("requests", "2.0"))

    def test_pip_range(self):
        self.assertEqual(split_name_version("requests>=2.0", "pip"), ("requests", None))

    def test_cargo(self):
        self.assertEqual(split_name_version("serde@1.0", "cargo"), ("serde", "1.0"))

    def test_composer(self):
        self.assertEqual(split_name_version("foo/bar:^1.0", "composer"), ("foo/bar", "^1.0"))


if __name__ == "__main__":
    unittest.main()