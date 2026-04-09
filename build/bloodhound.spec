# PyInstaller spec file for PCAP Detective
# Build with: pyinstaller build/bloodhound.spec

import sys
import os

block_cipher = None

a = Analysis(
    ['../app/main.py'],
    pathex=['..'],
    binaries=[],
    datas=[
        ('../app/resources/logo.png', 'app/resources'),
        ('../app/resources/sample_capture.pcap', 'app/resources'),
    ],
    hiddenimports=[
        'scapy.all',
        'scapy.layers.inet',
        'scapy.layers.dns',
        'scapy.layers.tls',
        'scapy.layers.http',
        'scapy.layers.smb',
        'scapy.layers.ntlm',
        'numpy',
        'cryptography',
        'PySide6.QtCharts',
    ],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=['tkinter', 'unittest'],
    noarchive=False,
    optimize=0,
    cipher=block_cipher,
)

pyz = PYZ(a.pure, a.zipped_data, cipher=block_cipher)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='PCAP Detective',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=False,
    disable_windowed_traceback=False,
)

coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='PCAP Detective',
)

if sys.platform == 'darwin':
    app = BUNDLE(
        coll,
        name='PCAP Detective.app',
        icon='icon.icns',
        bundle_identifier='com.bardsec.pcap-detective',
        info_plist={
            'CFBundleName': 'PCAP Detective',
            'CFBundleDisplayName': 'PCAP Detective',
            'CFBundleShortVersionString': '2.1.0',
            'NSHighResolutionCapable': True,
            'LSMinimumSystemVersion': '12.0',
            'NSHumanReadableCopyright': 'Copyright \u00a9 2026 BardSec',
            'LSApplicationCategoryType': 'public.app-category.utilities',
        },
    )
