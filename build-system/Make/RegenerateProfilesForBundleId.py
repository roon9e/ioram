#!/usr/bin/env python3
"""
Regenerate fake-codesigning provisioning profiles for the new `bundle_id`.
This script performs the following steps:
1. Reads the `bundle_id` and `team_id` from `build-system/appstore-configuration.json`.
2. Decodes the existing `.mobileprovision` file.
3. Modifies fields such as `application-identifier`, `application-groups`, and `TeamIdentifier`.
4. Resigns the profiles using `SelfSigned.p12` to generate new ones.
Must be run on macOS (requires the `security` and `openssl` commands).
"""

import json
import os
import sys
import tempfile
import plistlib
import argparse
import subprocess
import base64

from BuildEnvironment import run_executable_with_output


def setup_temp_keychain(p12_path, p12_password=''):
    """Create a temporary keychain and import the p12 certificate"""
    keychain_name = 'regenerate-profiles-temp.keychain'
    keychain_password = 'temp123'

    # Delete if it exists
    run_executable_with_output('security', arguments=['delete-keychain', keychain_name], check_result=False)

    # Create a keychain
    run_executable_with_output('security', arguments=[
        'create-keychain', '-p', keychain_password, keychain_name
    ], check_result=True)

    # Add to search list
    existing = run_executable_with_output('security', arguments=['list-keychains', '-d', 'user'])
    run_executable_with_output('security', arguments=[
        'list-keychains', '-d', 'user', '-s', keychain_name, existing.replace('"', '')
    ], check_result=True)

    # Unlock and set access permissions
    run_executable_with_output('security', arguments=['set-keychain-settings', keychain_name])
    run_executable_with_output('security', arguments=[
        'unlock-keychain', '-p', keychain_password, keychain_name
    ])

    # Import certificate
    run_executable_with_output('security', arguments=[
        'import', p12_path, '-k', keychain_name, '-P', p12_password,
        '-T', '/usr/bin/codesign', '-T', '/usr/bin/security'
    ], check_result=True)

    # Set the partition list
    run_executable_with_output('security', arguments=[
        'set-key-partition-list', '-S', 'apple-tool:,apple:', '-k', keychain_password, keychain_name
    ], check_result=True)

    return keychain_name


def cleanup_temp_keychain(keychain_name):
    """Delete the temporary keychain"""
    run_executable_with_output('security', arguments=['delete-keychain', keychain_name], check_result=False)


def _extract_pem_from_p12(p12_path, p12_password=''):
    """Attempt to extract the PEM certificate from the p12 file; try the `-legacy` option first, and fall back if it fails."""
    for legacy_flag in [['-legacy'], []]:
        proc = subprocess.Popen(
            ['openssl', 'pkcs12', '-in', p12_path, '-passin', 'pass:' + p12_password, '-nokeys'] + legacy_flag,
            stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        cert_pem, stderr = proc.communicate()
        if proc.returncode == 0 and b'BEGIN CERTIFICATE' in cert_pem:
            return cert_pem
        print('openssl pkcs12 attempt {} failed: {}'.format(legacy_flag, stderr.decode('utf-8', errors='ignore').strip()))
    return None


def _parse_cn_from_subject(subject):
    """Extract the Common Name from the `subject` string, supporting various OpenSSL output formats."""
    import re

    # Entry 1: subject= C= US, O =..., CN = Apple Distribution: ... (TEAM), ...
    if 'CN = ' in subject:
        cn_part = subject.split('CN = ')[-1]
        # In the oneline format, RDN is separated by ",X=", X is usually C/O/OU/L/ST/CN, etc.
        next_rdn_pos = len(cn_part)
        rdn_prefixes = [
            ", C = ",
            ", O = ",
            ", OU = ",
            ", L = ",
            ", ST = ",
            ", CN = ",
        ]
        for rdn_prefix in rdn_prefixes:
            pos = cn_part.find(rdn_prefix)
            if pos != -1 and pos < next_rdn_pos:
                next_rdn_pos = pos
        return cn_part[:next_rdn_pos].strip()

    # Entry 2: /C=US/O=.../CN=Apple Distribution: ... (Team)/...
    if '/CN=' in subject:
        match = re.search(r'/CN=([^/]+)', subject)
        if match:
            return match.group(1).strip()

    return None


def get_signing_identity_from_p12(p12_path, p12_password='', certs_dir=None):
    """Extract the signing identity (Common Name) from p12; if this fails, attempt to use Public.cer from the same directory."""
    cert_pem = _extract_pem_from_p12(p12_path, p12_password)
    if cert_pem is not None:
        proc2 = subprocess.Popen(
            ['openssl', 'x509', '-noout', '-subject', '-nameopt', 'oneline,-esc_msb'],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
        )
        subject, _ = proc2.communicate(cert_pem)
        subject = subject.decode('utf-8').strip()
        print('Certificate subject from p12: {}'.format(subject))
        cn = _parse_cn_from_subject(subject)
        if cn:
            return cn

    # Fallback: Read from Public.cer in the same directory
    if certs_dir is not None:
        cer_path = os.path.join(certs_dir, 'Public.cer')
        if os.path.exists(cer_path):
            print('Falling back to Public.cer: {}'.format(cer_path))
            proc = subprocess.Popen(
                ['openssl', 'x509', '-in', cer_path, '-inform', 'DER', '-noout', '-subject', '-nameopt', 'oneline,-esc_msb'],
                stdout=subprocess.PIPE, stderr=subprocess.PIPE
            )
            subject, _ = proc.communicate()
            subject = subject.decode('utf-8').strip()
            print('Certificate subject from cer: {}'.format(subject))
            cn = _parse_cn_from_subject(subject)
            if cn:
                return cn

    return None


def get_certificate_base64_from_p12(p12_path, p12_password=''):
    """Extract the certificate from the p12 file and convert it to Base64."""
    cert_pem = _extract_pem_from_p12(p12_path, p12_password)
    if cert_pem is None:
        print('Could not extract certificate from {}'.format(p12_path))
        sys.exit(1)

    proc2 = subprocess.Popen(
        ['openssl', 'x509', '-outform', 'DER'],
        stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    )
    cert_der, _ = proc2.communicate(cert_pem)

    return base64.b64encode(cert_der).decode('utf-8')


def decode_provisioning_profile(source):
    """Use OpenSSL to decode a .mobileprovision file into a plist dictionary."""
    profile_data = run_executable_with_output('openssl', arguments=[
        'smime',
        '-inform',
        'der',
        '-verify',
        '-noverify',
        '-in',
        source
    ], decode=False, stderr_to_stdout=False, check_result=True)
    return plistlib.loads(profile_data)


def sign_provisioning_profile(plist_file, destination, signing_identity, keychain_name):
    """Use `security cms` to sign the plist file."""
    run_executable_with_output('security', arguments=[
        'cms', '-S', '-k', keychain_name, '-N', signing_identity, '-i', plist_file, '-o', destination
    ], check_result=True)


def update_profile_for_bundle_id(profile_dict, new_bundle_id, new_team_id, suffix):
    """
    Update the profile dict to match the new bundle_id.
    Parameters:
        profile_dict: The decoded plist dict
        new_bundle_id: The new bundle ID, e.g., ph.mimosa.Mimosa
        new_team_id: The new team ID
        suffix: The suffix for the application-identifier, e.g., '', '.Share', or '.Widget'
    """
    # Update application-identifier
    profile_dict['Entitlements']['application-identifier'] = new_team_id + '.' + new_bundle_id + suffix

    # Update application-groups
    if 'com.apple.security.application-groups' in profile_dict['Entitlements']:
        new_groups = []
        for group in profile_dict['Entitlements']['com.apple.security.application-groups']:
            if group.startswith('group.'):
                new_groups.append('group.' + new_bundle_id)
            else:
                new_groups.append(group)
        profile_dict['Entitlements']['com.apple.security.application-groups'] = new_groups

    # Update ApplicationIdentifierPrefix
    if 'ApplicationIdentifierPrefix' in profile_dict:
        profile_dict['ApplicationIdentifierPrefix'] = [new_team_id + '.']

    # Update TeamIdentifier
    if 'TeamIdentifier' in profile_dict:
        profile_dict['TeamIdentifier'] = [new_team_id]

    # Update AppIDName (optional, for readability)
    if 'AppIDName' in profile_dict:
        profile_dict['AppIDName'] = new_bundle_id + suffix

    return profile_dict


def regenerate_profiles(source_path, destination_path, certs_path, new_bundle_id, new_team_id):
    """Bulk regenerate provisioning profiles"""
    p12_path = os.path.join(certs_path, 'SelfSigned.p12')

    if not os.path.exists(p12_path):
        print('{} does not exist'.format(p12_path))
        sys.exit(1)

    if not os.path.exists(destination_path):
        os.makedirs(destination_path, exist_ok=True)

    p12_password = ''  # fake-codesigning uses an empty password
    certificate_data = get_certificate_base64_from_p12(p12_path, p12_password)
    signing_identity = get_signing_identity_from_p12(p12_path, p12_password, certs_dir=certs_path)

    if not signing_identity:
        print('Could not extract signing identity from {}'.format(p12_path))
        sys.exit(1)

    print('Using signing identity: {}'.format(signing_identity))

    keychain_name = setup_temp_keychain(p12_path, p12_password)

    # File name -> application-identifier suffix mapping
    profile_name_mapping = {
        'Telegram': '',
        'Intents': '.SiriIntents',
        'NotificationContent': '.NotificationContent',
        'NotificationService': '.NotificationService',
        'Share': '.Share',
        'WatchApp': '.watchkitapp',
        'WatchExtension': '.watchkitapp.watchkitextension',
        'Widget': '.Widget',
        'BroadcastUpload': '.BroadcastUpload'
    }

    try:
        for file_name in sorted(os.listdir(source_path)):
            if not file_name.endswith('.mobileprovision'):
                continue

            source_file = os.path.join(source_path, file_name)
            profile_base_name = file_name.replace('.mobileprovision', '')
            suffix = profile_name_mapping.get(profile_base_name, '')

            print('Processing {} -> suffix="{}"'.format(file_name, suffix))

            # Decode original profile
            profile_dict = decode_provisioning_profile(source_file)

            # Update fields related to the bundle ID
            updated_dict = update_profile_for_bundle_id(profile_dict, new_bundle_id, new_team_id, suffix)

            # Write to a temporary plist file
            parsed_plist_file = tempfile.mktemp()
            with open(parsed_plist_file, 'wb') as f:
                plistlib.dump(updated_dict, f)

            # Remove old DeveloperCertificates
            while True:
                result = run_executable_with_output('plutil', arguments=['-remove', 'DeveloperCertificates.0', parsed_plist_file], check_result=False)
                if result is None or 'Could not' in str(result) or result == '':
                    check = run_executable_with_output('plutil', arguments=['-extract', 'DeveloperCertificates.0', 'raw', parsed_plist_file], check_result=False)
                    if check is None or 'Could not' in str(check):
                        break

            # Insert a new certificate and remove the old signature
            run_executable_with_output('plutil', arguments=['-insert', 'DeveloperCertificates.0', '-data', certificate_data, parsed_plist_file])
            run_executable_with_output('plutil', arguments=['-remove', 'DER-Encoded-Profile', parsed_plist_file])

            # Re-sign
            destination_file = os.path.join(destination_path, file_name)
            sign_provisioning_profile(parsed_plist_file, destination_file, signing_identity, keychain_name)

            os.unlink(parsed_plist_file)

        print('Done. Generated {} profiles.'.format(
            len([f for f in os.listdir(destination_path) if f.endswith('.mobileprovision')])
        ))
    finally:
        cleanup_temp_keychain(keychain_name)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Regenerate provisioning profiles for a new bundle id')
    parser.add_argument('--configurationPath', required=True, help='Path to build configuration JSON')
    parser.add_argument('--sourceProfiles', required=True, help='Path to source provisioning profiles directory')
    parser.add_argument('--destinationProfiles', required=True, help='Path to output provisioning profiles directory')
    parser.add_argument('--certsPath', required=True, help='Path to certificates directory containing SelfSigned.p12')

    args = parser.parse_args()

    with open(args.configurationPath) as f:
        config = json.load(f)

    new_bundle_id = config['bundle_id']
    new_team_id = config['team_id']

    print('Regenerating profiles for bundle_id={}, team_id={}'.format(new_bundle_id, new_team_id))
    regenerate_profiles(args.sourceProfiles, args.destinationProfiles, args.certsPath, new_bundle_id, new_team_id)