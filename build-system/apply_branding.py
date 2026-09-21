#!/usr/bin/env python3
"""
apply_branding.py - Apply a single branding/datacenter configuration over a clean
upstream Telegram-iOS tree, in place.

Usage:
    python3 build-system/apply_branding.py build-system/branding/branding.json [repo_root]

The RSA public key is read from server_rsa.pub located next to the branding
JSON file (PKCS#1 PEM or bare base64). Everything the script rewrites must have
its upstream anchor text present; if a required transform cannot be applied the
script exits non-zero so CI fails loudly instead of shipping a misbranded build.
"""
import json
import os
import re
import sys

WIDTH = 64


def read(path):
    with open(path, 'r', encoding='utf-8', newline='') as f:
        return f.read()


def write(path, text):
    with open(path, 'w', encoding='utf-8', newline='') as f:
        f.write(text)


def warn(msg):
    print('[apply_branding] WARNING: ' + msg)


class Branding:
    def __init__(self, path, root):
        with open(path, 'r', encoding='utf-8') as f:
            self.cfg = json.load(f)
        self.root = root
        self.config_dir = os.path.dirname(os.path.abspath(path))
        self.failures = []

    def report(self, ok_flag, what):
        if ok_flag:
            print('[apply_branding] ok: ' + what)
        else:
            self.failures.append(what)
            warn('missing upstream anchor: ' + what)

    def path(self, rel):
        return os.path.join(self.root, rel)

    def require(self, rel, transformed, what):
        text = read(self.path(rel))
        new_text = transformed(text)
        if new_text is text or new_text == text:
            self.report(False, what)
            return
        write(self.path(rel), new_text)
        self.report(True, what)

    # ------- building blocks -------

    def rsa_key(self):
        pem_path = os.path.join(self.config_dir, 'server_rsa.pub')
        if not os.path.isfile(pem_path):
            self.failures.append('missing RSA key file: ' + pem_path)
            return None
        with open(pem_path, 'r', encoding='utf-8') as f:
            content = f.read()
        content = content.replace('-----BEGIN RSA PUBLIC KEY-----', '')
        content = content.replace('-----END RSA PUBLIC KEY-----', '')
        content = re.sub(r'\s+', '', content)
        if not content:
            self.failures.append('empty RSA key file: ' + pem_path)
            return None
        return content

    def substitute(self, text, old, new, what):
        if old not in text:
            return text, False
        return text.replace(old, new), True

    def require_replace(self, rel, old, new, what):
        def transform(text):
            out, ok = self.substitute(text, old, new, what)
            return out if ok else text
        self.require(rel, transform, what)

    def require_subst_all(self, rel, pairs, what):
        def transform(text):
            for old, new in pairs:
                if old not in text:
                    return text
                text = text.replace(old, new)
            return text
        self.require(rel, transform, what)

    # ------- transforms -------

    def apply_datacenter(self, rel_network, rel_mtdc, rel_enc, rel_account):
        d = self.cfg['datacenter']
        dc_id = str(d['id'])
        ip = d['ip']
        port = str(d['port'])
        restrict = 'true' if d.get('restrict_to_tcp') else 'false'

        seed_block_old = (
            '            if testingEnvironment {\n'
            '                seedAddressList = [\n'
            '                    1: ["149.154.175.10"],\n'
            '                    2: ["149.154.167.40"],\n'
            '                    3: ["149.154.175.117"]\n'
            '                ]\n'
            '            } else {\n'
            '                seedAddressList = [\n'
            '                    1: ["149.154.175.50", "2001:b28:f23d:f001::a"],\n'
            '                    2: ["149.154.167.50", "95.161.76.100", "2001:67c:4e8:f002::a"],\n'
            '                    3: ["149.154.175.100", "2001:b28:f23d:f003::a"],\n'
            '                    4: ["149.154.167.91", "2001:67c:4e8:f004::a"],\n'
            '                    5: ["149.154.171.5", "2001:b28:f23f:f005::a"]\n'
            '                ]\n'
            '            }'
        )
        seed_block_new = (
            '            seedAddressList = [\n'
            '                ' + dc_id + ': ["' + ip + '"]\n'
            '            ]'
        )
        addr_old = 'MTDatacenterAddress(ip: $0, port: 443, preferForMedia: false, restrictToTcp: false'
        addr_new = 'MTDatacenterAddress(ip: $0, port: ' + port + ', preferForMedia: false, restrictToTcp: ' + restrict
        self.require_subst_all(rel_network, [(seed_block_old, seed_block_new), (addr_old, addr_new)], 'Network.swift datacenter seed addresses')

        key = self.rsa_key()
        if key is None:
            return
        for rel in (rel_mtdc, rel_enc):
            self.require(rel, lambda text, k=key: self.replace_rsa_blobs(text, k), 'RSA public key in ' + rel)

        def account_transform(text):
            # Upstream gates the datacenter by build flavor (#if DEBUG 1 / #else 2);
            # the fork forces the custom datacenter unconditionally.
            m = re.search(
                r'(?m)^( {4,})#if DEBUG\n'
                r'\1let initialDatacenterId: Int = \d+\n'
                r'\1#else\n'
                r'\1let initialDatacenterId: Int = \d+\n'
                r'\1#endif\n',
                text,
            )
            if m is None:
                return text
            pref = m.group(1)
            block = pref + 'let initialDatacenterId: Int = ' + dc_id + '\n'
            return text[:m.start()] + block + text[m.end():]
        self.require(rel_account, account_transform, 'Account.swift initialDatacenterId block')

    @staticmethod
    def replace_rsa_blobs(text, key_b64):
        lines = text.split('\n')
        out = []
        i = 0
        replaced = 0
        while i < len(lines):
            line = lines[i]
            if 'MIIB' in line and '\\n"' in line:
                j = i
                while j < len(lines) and 'AQAB' not in lines[j]:
                    j += 1
                if j >= len(lines):
                    out.append(line)
                    i += 1
                    continue
                indent = line[:len(line) - len(line.lstrip())]
                for k in range(0, len(key_b64), WIDTH):
                    out.append(indent + '"' + key_b64[k:k + WIDTH] + '\\n"')
                i = j + 1
                replaced += 1
            else:
                out.append(line)
                i += 1
        if replaced == 0:
            return text
        return '\n'.join(out)

    def apply_workarounds(self, rel_appdelegate, rel_buildconfig):
        w = self.cfg.get('workarounds', {})

        if w.get('app_group_fallback'):
            def ad_transform(text):
                m = re.search(
                    r'(?m)^( {4,})let maybeAppGroupUrl = FileManager\.default\.containerURL'
                    r'\(forSecurityApplicationGroupIdentifier: appGroupName\)$',
                    text
                )
                if m is None:
                    return text
                pref = m.group(1)
                block = (
                    pref + '// Original: Use App Group shared container\n' +
                    pref + '// let maybeAppGroupUrl = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupName)\n' +
                    '\n' +
                    pref + '// Modified: Fall back to the app\'s private container if App Group is unavailable\n' +
                    pref + '// Note: App Groups cannot be used with self-signed builds using a free Apple ID; \n' +
                    pref + '// with this fallback, the main app launches normally, but extensions (Share, Widget, Watch, Siri, etc.) will cease to function.\n' +
                    pref + '// To restore: Uncomment the original code above and comment out this fallback logic below.\n' +
                    pref + 'var maybeAppGroupUrl = FileManager.default.containerURL(forSecurityApplicationGroupIdentifier: appGroupName)\n' +
                    pref + 'if maybeAppGroupUrl == nil {\n' +
                    pref + '    maybeAppGroupUrl = FileManager.default.urls(for: .documentDirectory, in: .userDomainMask).first\n' +
                    pref + '}'
                )
                return text[:m.start()] + block + text[m.end():]
            self.require(rel_appdelegate, ad_transform, 'AppDelegate.swift app group fallback')

        if w.get('aps_environment_fallback'):
            old = (
                "                        print('Provisioning profile at {} does not include an aps-environment entitlement'.format(file_path))\n"
                "                        sys.exit(1)"
            )
            new = (
                "                        print('Provisioning profile at {} does not include an aps-environment entitlement; continuing without push notifications'.format(file_path))\n"
                '                        return ""'
            )
            self.require_replace(rel_buildconfig, old, new, 'BuildConfiguration.py aps-environment fallback')

    def apply_appstore_config(self, rel):
        g = self.cfg['general']
        a = self.cfg['appstore']

        def transform(text):
            reps = [
                ('"bundle_id"', g['bundle_id']),
                ('"is_appstore_build"', a['is_appstore_build']),
                ('"app_specific_url_scheme"', g['app_specific_url_scheme']),
            ]
            for key, value in reps:
                pat = re.compile(r'("' + re.escape(key[1:-1]) + r'"\s*:\s*)"[^"]*"')
                m = pat.search(text)
                if m is None:
                    return text
                text = text[:m.start()] + m.group(1) + '"' + value + '"' + text[m.end():]
            bools = {
                'enable_siri': str(a['enable_siri']).lower(),
                'enable_icloud': str(a['enable_icloud']).lower(),
            }
            for key, value in bools.items():
                pat = re.compile(r'("' + key + r'"\s*:\s*)(true|false)')
                m = pat.search(text)
                if m is None:
                    return text
                text = text[:m.start()] + m.group(1) + value + text[m.end():]
            return text
        self.require(rel, transform, 'appstore-configuration.json bundle/scheme')

    def apply_build(self, rel):
        g = self.cfg['general']
        host = g['host']
        name = g['app_name']

        def transform(text):
            old_gate = 'associated_domains_fragment = "" if telegram_bundle_id not in official_bundle_ids else """'
            if old_gate not in text:
                return text
            text = text.replace(old_gate, 'associated_domains_fragment = """')

            old_domains = (
                '    <string>applinks:telegram.me</string>\n'
                '    <string>applinks:t.me</string>\n'
                '    <string>applinks:*.t.me</string>\n'
                '    <string>webcredentials:t.me</string>\n'
                '    <string>webcredentials:telegram.org</string>'
            )
            if old_domains not in text:
                return text
            new_domains = (
                '    <string>applinks:' + host + '</string>\n'
                '    <string>applinks:*.' + host + '</string>\n'
                '    <string>applinks:' + host + '?mode=developer</string>\n'
                '    <string>applinks:*.' + host + '?mode=developer</string>'
            )
            text = text.replace(old_domains, new_domains)

            pairs = [
                ('<string>telegram</string>', '<string>' + g['url_scheme'] + '</string>'),
                ('<string>tg</string>', '<string>' + g['url_scheme_short'] + '</string>'),
                ('<string>Telegram</string>', '<string>' + name + '</string>'),
                ('Telegram stores your contacts', name + ' stores your contacts'),
                ('send your location to your friends, Telegram needs access', 'send your location to your friends, ' + name + ' needs access'),
                ('app_icons = [ ":{}_icon".format(name) for name in composer_icon_folders ],', 'app_icons = [":DefaultAppIcon"],'),
                ('composer_icon_folders = ["Telegram"]', 'composer_icon_folders = []'),
            ]
            for old, new in pairs:
                if old not in text:
                    return text
                text = text.replace(old, new)
            return text
        self.require(rel, transform, 'BUILD scheme/name/associated-domains')

    def apply_url_handling(self, rel):
        g = self.cfg['general']
        host = g['host']
        short = g['url_scheme_short']
        long = g['url_scheme']

        def transform(text):
            pairs = [
                ('private let baseTelegramMePaths = [\n    "telegram.me",\n    "t.me", "telegram.dog"\n]',
                 'private let baseTelegramMePaths = [\n    "' + host + '"\n]'),
                ('private let telegramWebShortLinkHosts = [\n    "a.t.me", \n    "k.t.me",\n    "z.t.me"\n]',
                 'private let telegramWebShortLinkHosts = [\n    "a.' + host + '",\n    "k.' + host + '",\n    "z.' + host + '"\n]'),
                ('"t.me/iv?",', '"' + host + '/iv?",'),
                ('url: "https://t.me/\\(query)"', 'url: "https://' + host + '/\\(query)"'),
                ('parsedUrl.scheme == "tg"', '(parsedUrl.scheme == "' + short + '" || parsedUrl.scheme == "' + long + '")'),
            ]
            for old, new in pairs:
                if old not in text:
                    return text
                text = text.replace(old, new)

            old_anchor = (
                '            if isTelegramWebShortLink(url) {\n'
                '                return .single(.result(.externalUrl(url)))\n'
                '            }\n'
                '\n'
                '            for basePath in baseTelegramMePaths {'
            )
            if old_anchor not in text:
                return text
            custom = (
                '            if isTelegramWebShortLink(url) {\n'
                '                return .single(.result(.externalUrl(url)))\n'
                '            }\n'
                '\n'
                '            let customSchemes = ["' + short + '://", "' + long + '://"]\n'
                '            for customScheme in customSchemes {\n'
                '                if url.lowercased().hasPrefix(customScheme) {\n'
                '                    var query = String(url[url.index(url.startIndex, offsetBy: customScheme.count)...])\n'
                '                    if query.hasPrefix("resolve?") || query.hasPrefix("resolve/?") {\n'
                '                        if let questionIndex = query.range(of: "?")?.upperBound {\n'
                '                            let paramsString = String(query[questionIndex...])\n'
                '                            var params: [String: String] = [:]\n'
                '                            for param in paramsString.components(separatedBy: "&") {\n'
                '                                let parts = param.components(separatedBy: "=")\n'
                '                                if parts.count == 2 {\n'
                '                                    params[parts[0]] = parts[1]\n'
                '                                }\n'
                '                            }\n'
                '                            if let domain = params["domain"] {\n'
                '                                var rebuilt = domain\n'
                '                                if let start = params["start"] {\n'
                '                                    rebuilt += "?start=\\(start)"\n'
                '                                } else if let post = params["post"] {\n'
                '                                    rebuilt += "/\\(post)"\n'
                '                                }\n'
                '                                query = rebuilt\n'
                '                            }\n'
                '                        }\n'
                '                    }\n'
                '                    if let internalUrl = parseInternalUrl(sharedContext: context.sharedContext, context: context, query: query) {\n'
                '                        return resolveInternalUrl(context: context, url: internalUrl)\n'
                '                        |> map { result -> ResolveUrlResult in\n'
                '                            switch result {\n'
                '                            case .progress:\n'
                '                                return .progress\n'
                '                            case let .result(resolved):\n'
                '                                if let resolved = resolved {\n'
                '                                    return .result(resolved)\n'
                '                                } else {\n'
                '                                    return .result(.externalUrl(url))\n'
                '                                }\n'
                '                            }\n'
                '                        }\n'
                '                    }\n'
                '                }\n'
                '            }\n'
                '\n'
                '            for basePath in baseTelegramMePaths {'
            )
            return text.replace(old_anchor, custom)
        self.require(rel, transform, 'UrlHandling.swift custom schemes')

    def apply_url_scheme_plists(self, rels):
        # Info.plist / InfoBazel.plist: only the legacy short scheme is rebranded.
        short = self.cfg['general']['url_scheme_short']
        for rel in rels:
            self.require_replace(rel, '<string>tg</string>', '<string>' + short + '</string>', rel + ' legacy URL scheme')

    def apply_strings_files(self, rels):
        for rel in rels:
            self.apply_optional_file(rel, self.rebrand_strings_transform, rel + ' brand strings')

    def apply_optional_file(self, rel, transform, what):
        path = self.path(rel)
        text = read(path)
        new_text = transform(text)
        if new_text != text:
            write(path, new_text)
            print('[apply_branding] ok: ' + what)
        else:
            print('[apply_branding] ok (no tokens): ' + what)

    def rebrand_strings_transform(self, text):
        host = self.cfg['general']['host']
        name = self.cfg['general']['app_name']
        short = self.cfg['general']['url_scheme_short']
        lines = text.split('\n')
        out = []
        for line in lines:
            m = re.match(r'^("[^"]*"\s*=\s*)(.*)$', line)
            if m is None:
                out.append(line)
                continue
            value = m.group(2)
            new_value = value.replace('t.me', host)
            new_value = new_value.replace('telegram.org', host)
            new_value = new_value.replace('tg://', short + '://')
            new_value = re.sub(r'\bTelegram\b', name, new_value, flags=re.IGNORECASE)
            out.append(m.group(1) + new_value)
        return '\n'.join(out)

    def apply_plist_phrases(self, rels):
        # AppIntentVocabulary.plist: the brand name appears only inside <string> values.
        for rel in rels:
            self.apply_optional_file(
                rel,
                lambda text: self.rebrand_plist_transform(text),
                rel + ' brand phrases',
            )

    def rebrand_plist_transform(self, text):
        name = self.cfg['general']['app_name']
        return re.sub(r'\bTelegram\b', name, text, flags=re.IGNORECASE)


def lproj_files(root, kind):
    directory = os.path.join(root, 'Telegram', 'Telegram-iOS')
    result = []
    if os.path.isdir(directory):
        for entry in sorted(os.listdir(directory)):
            if entry.endswith('.lproj'):
                candidate = os.path.join(directory, entry, kind)
                if os.path.isfile(candidate):
                    result.append(os.path.relpath(candidate, root))
    return result


def main(argv):
    if len(argv) < 2:
        print('Usage: apply_branding.py <branding.json> [repo_root]')
        return 1
    root = argv[2] if len(argv) > 2 else os.getcwd()
    b = Branding(argv[1], root)

    b.apply_datacenter(
        'submodules/TelegramCore/Sources/Network/Network.swift',
        'submodules/MtProtoKit/Sources/MTDatacenterAuthMessageService.m',
        'submodules/MtProtoKit/Sources/MTEncryption.m',
        'submodules/TelegramCore/Sources/Account/Account.swift',
    )
    b.apply_appstore_config('build-system/appstore-configuration.json')
    b.apply_build('Telegram/BUILD')
    b.apply_url_handling('submodules/UrlHandling/Sources/UrlHandling.swift')
    b.apply_url_scheme_plists([
        'Telegram/Telegram-iOS/Info.plist',
        'Telegram/Telegram-iOS/InfoBazel.plist',
    ])
    b.apply_strings_files([
        'Telegram/Share/en.lproj/Localizable.strings',
        'Telegram/WidgetKitWidget/en.lproj/Localizable.strings',
        'Telegram/Telegram-iOS/en.lproj/Localizable.strings',
    ])
    b.apply_strings_files(lproj_files(root, 'InfoPlist.strings'))
    b.apply_plist_phrases(lproj_files(root, 'AppIntentVocabulary.plist'))
    b.apply_workarounds(
        'submodules/TelegramUI/Sources/AppDelegate.swift',
        'build-system/Make/BuildConfiguration.py',
    )

    if b.failures:
        print('[apply_branding] %d transform(s) could not be applied:' % len(b.failures))
        for what in b.failures:
            print('  - ' + what)
        return 1
    print('[apply_branding] done.')
    return 0


if __name__ == '__main__':
    sys.exit(main(sys.argv))