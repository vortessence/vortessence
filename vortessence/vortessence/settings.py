"""
Django settings for the Vortessence project.

For more information on this file, see
https://docs.djangoproject.com/en/1.7/topics/settings/

For the full list of settings and their values, see
https://docs.djangoproject.com/en/1.7/ref/settings/
"""

# Build paths inside the project like this: os.path.join(BASE_DIR, ...)
import os

BASE_DIR = os.path.dirname(os.path.dirname(__file__))

# SECURITY WARNING: keep the secret key used in production secret!
SECRET_KEY = 'h1a%)p(h%oter6__@fef%1#n5f12+e&$1$1y!hzv--spb%xc%7'

# SECURITY WARNING: don't run with debug turned on in production!
DEBUG = True

TEMPLATE_DEBUG = True

ALLOWED_HOSTS = []


# Application definition

INSTALLED_APPS = (
    'django.contrib.admin',
    'django.contrib.auth',
    'django.contrib.contenttypes',
    'django.contrib.sessions',
    'django.contrib.messages',
    'django.contrib.staticfiles',
    'vortessence',
)

MIDDLEWARE_CLASSES = (
    'django.contrib.sessions.middleware.SessionMiddleware',
    'django.middleware.common.CommonMiddleware',
    'django.middleware.csrf.CsrfViewMiddleware',
    'django.contrib.auth.middleware.AuthenticationMiddleware',
    'django.contrib.messages.middleware.MessageMiddleware',
    'django.middleware.clickjacking.XFrameOptionsMiddleware',
)

ROOT_URLCONF = 'vortessence.urls'

WSGI_APPLICATION = 'vortessence.wsgi.application'


# Database
# https://docs.djangoproject.com/en/1.7/ref/settings/#databases

DATABASES = {
    'default': {
        'ENGINE': 'django.db.backends.mysql',
        'NAME': 'vortessence',
        'USER': 'vortessence',
        'PASSWORD': 'vortessence',
        'HOST': '127.0.0.1',
        'PORT': '3306'
    }
}

LOGGING = {
    'version': 1,
    'disable_existing_loggers': True,
    'formatters': {
        'verbose': {
            'format': '%(levelname)s %(asctime)s %(module)s %(process)d %(thread)d %(message)s'
        },
        'simple': {
            'format': '%(levelname)s %(message)s'
        },
    },
    'handlers': {
        # 'file':{
        #     'level': 'DEBUG',
        #     'class': 'logging.FileHandler',
        #     'filename': '/var/log/vortessence.log',
        #     'formatter': 'verbose'
        # },
        'db': {
            'level': 'DEBUG',
            'class': 'vortessence.loggers.DbLogHandler',
            'formatter': 'verbose'
        }
    },
    'loggers': {
        # 'vortessence': {
        #     'handlers': ['file'],
        #     'level': 'DEBUG',
        #     'propagate': False,
        #     },
        'vortessence': {
            'handlers': ['db'],
            'level': 'DEBUG',
            'propagate': False,
        }
    }
}

# Internationalization
# https://docs.djangoproject.com/en/1.7/topics/i18n/

LANGUAGE_CODE = 'en-us'

TIME_ZONE = 'UTC'

USE_I18N = True

USE_L10N = True

USE_TZ = True


# CUSTOM SETTINGS VORTESSENCE
python_path = "/usr/bin/python"
vort_path = {
    "upload": "/vagrant/data/upload",
    "ramdisk": "/media/tmpfs",
    "target": "/vagrant/data/target"
}

malfind_dump_path = "/media/tmpfs/malfind_dumps"

vol_path = os.path.join(os.path.dirname(__file__), os.pardir, "volatility25", "vol.py")
vol_plugins = [
    ("pslist", "--output=json", None), ("dlllist", "--output=json", None), ("netscan", "--output=json", None),
    ("idt", "--output=json", None), ("gdt", "--output=json", None), ("cmdline", "--output=json", None),
    ("callbacks", "--output=json", None), ("driverirp", "--output=json", None), ("timers", "--output=json", None),
    ("unloadedmodules", "--output=json", None), ("getsids", "--output=json", None), ("filescan", "--output=json", None),
    ("threads", "--output=json", None), ("ssdt", "--output=json", "-v"),
    ("malfind", "--output=json", "--dump-dir=" + malfind_dump_path), ("verinfo", "--output=json", None),
    ("vadinfo", "--output=json", None), ("ldrmodules", "--output=json", None), ("modscan", "--output=json", None),
    ("svcscan", "--output=json", "-v"), ("handles", "--output=json", None)]

x86_only_plugins = ["idt", "gdt"]

slow_vol_plugins = [("apihooks", "--output=json", None)]

non_recursive_registry_keys = ["Microsoft\Windows\CurrentVersion\Run", "Microsoft\Windows\CurrentVersion\RunOnce", \
                               "Microsoft\Windows NT\CurrentVersion\Winlogon", \
                               "Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad", \
                               "ControlSet001\Control\Session Manager", \
                               "Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler",
                               "Software\Microsoft\Windows\CurrentVersion\Run"]

recursive_registry_keys = ["ControlSet001\Services", "Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects"]

# known autostart keys
autostart_registry_keys = ["Control Panel\Desktop\Scrnsave.exe", \
                           "Software\Microsoft\Command Processor\Autorun", \
                           "Software\Microsoft\Ctf\LangBarAddin", \
                           "Software\Microsoft\Internet Explorer\Desktop\Components", \
                           "Software\Microsoft\Internet Explorer\Explorer Bars", \
                           "Software\Microsoft\Internet Explorer\Extensions", \
                           "Software\Microsoft\Internet Explorer\UrlSearchHooks", \
                           "Software\Microsoft\Windows NT\CurrentVersion\Drivers32", \
                           "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run", \
                           "Software\Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce", \
                           "Software\Microsoft\Windows NT\CurrentVersion\Windows\Load", \
                           "Software\Microsoft\Windows NT\CurrentVersion\Windows\Run", \
                           "Software\Microsoft\Windows NT\CurrentVersion\Winlogon\Shell", \
                           "Software\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers", \
                           "Software\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects", \
                           "Software\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", \
                           "Software\Microsoft\Windows\CurrentVersion\Policies\System\Shell", \
                           "Software\Microsoft\Windows\CurrentVersion\Run", \
                           "Software\Microsoft\Windows\CurrentVersion\RunOnce", \
                           "Software\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad", \
                           "Software\Policies\Microsoft\Windows\Control Panel\Desktop\Scrnsave.exe", \
                           "Software\Policies\Microsoft\Windows\System\Scripts\Logoff", \
                           "Software\Policies\Microsoft\Windows\System\Scripts\Logon", \
                           "Software\Wow6432Node\Classes\CLSID\{083863F1-70DE-11d0-BD40-00A0C911CE86}\Instance", \
                           "Software\Wow6432Node\Classes\CLSID\{7ED96837-96F0-4812-B211-F13C24117ED3}\Instance", \
                           "Software\Wow6432Node\Classes\CLSID\{ABE3B9A4-257D-4B97-BD1A-294AF496222E}\Instance", \
                           "Software\Wow6432Node\Classes\CLSID\{AC757296-3522-4E11-9862-C17BE5A1767E}\Instance", \
                           "Software\Wow6432Node\Microsoft\Internet Explorer\Explorer Bars", \
                           "Software\Wow6432Node\Microsoft\Internet Explorer\Extensions", \
                           "Software\Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32", \
                           "Software\Classes\*\ShellEx\ContextMenuHandlers", \
                           "Software\Classes\*\ShellEx\PropertySheetHandlers", \
                           "Software\Classes\.cmd", \
                           "Software\Classes\.exe", \
                           "Software\Classes\AllFileSystemObjects\ShellEx\ContextMenuHandlers", \
                           "Software\Classes\AllFileSystemObjects\ShellEx\DragDropHandlers", \
                           "Software\Classes\AllFileSystemObjects\ShellEx\PropertySheetHandlers", \
                           "Software\Classes\CLSID\{083863F1-70DE-11d0-BD40-00A0C911CE86}\Instance", \
                           "Software\Classes\CLSID\{7ED96837-96F0-4812-B211-F13C24117ED3}\Instance", \
                           "Software\Classes\CLSID\{ABE3B9A4-257D-4B97-BD1A-294AF496222E}\Instance", \
                           "Software\Classes\CLSID\{AC757296-3522-4E11-9862-C17BE5A1767E}\Instance", \
                           "Software\Classes\Directory\Background\ShellEx\ContextMenuHandlers", \
                           "Software\Classes\Directory\ShellEx\ContextMenuHandlers", \
                           "Software\Classes\Directory\Shellex\CopyHookHandlers", \
                           "Software\Classes\Directory\Shellex\DragDropHandlers", \
                           "Software\Classes\Directory\Shellex\PropertySheetHandlers", \
                           "Software\Classes\Drive\ShellEx\ContextMenuHandlers", \
                           "Software\Classes\Exefile\Shell\Open\Command\(Default)", \
                           "Software\Classes\Filter", \
                           "Software\Classes\Folder\Shellex\ColumnHandlers", \
                           "Software\Classes\Folder\ShellEx\ContextMenuHandlers", \
                           "Software\Classes\Folder\ShellEx\DragDropHandlers", \
                           "Software\Classes\Folder\ShellEx\ExtShellFolderViews", \
                           "Software\Classes\Folder\ShellEx\PropertySheetHandlers", \
                           "Software\Classes\Htmlfile\Shell\Open\Command\(Default)", \
                           "Software\Classes\Protocols\Filter", \
                           "Software\Classes\Protocols\Handler", \
                           "Classes\*\ShellEx\ContextMenuHandlers", \
                           "Classes\*\ShellEx\PropertySheetHandlers", \
                           "Classes\.cmd", \
                           "Classes\.exe", \
                           "Classes\AllFileSystemObjects\ShellEx\ContextMenuHandlers", \
                           "Classes\AllFileSystemObjects\ShellEx\DragDropHandlers", \
                           "Classes\AllFileSystemObjects\ShellEx\PropertySheetHandlers", \
                           "Classes\CLSID\{083863F1-70DE-11d0-BD40-00A0C911CE86}\Instance", \
                           "Classes\CLSID\{7ED96837-96F0-4812-B211-F13C24117ED3}\Instance", \
                           "Classes\CLSID\{ABE3B9A4-257D-4B97-BD1A-294AF496222E}\Instance", \
                           "Classes\CLSID\{AC757296-3522-4E11-9862-C17BE5A1767E}\Instance", \
                           "Classes\Directory\Background\ShellEx\ContextMenuHandlers", \
                           "Classes\Directory\ShellEx\ContextMenuHandlers", \
                           "Classes\Directory\Shellex\CopyHookHandlers", \
                           "Classes\Directory\Shellex\DragDropHandlers", \
                           "Classes\Directory\Shellex\PropertySheetHandlers", \
                           "Classes\Drive\ShellEx\ContextMenuHandlers", \
                           "Classes\Exefile\Shell\Open\Command\(Default)", \
                           "Classes\Filter", \
                           "Classes\Folder\Shellex\ColumnHandlers", \
                           "Classes\Folder\ShellEx\ContextMenuHandlers", \
                           "Classes\Folder\ShellEx\DragDropHandlers", \
                           "Classes\Folder\ShellEx\ExtShellFolderViews", \
                           "Classes\Folder\ShellEx\PropertySheetHandlers", \
                           "Classes\Htmlfile\Shell\Open\Command\(Default)", \
                           "Classes\Protocols\Filter", \
                           "Classes\Protocols\Handler", \
                           "Microsoft\Active Setup\Installed Components", \
                           "Microsoft\Command Processor\Autorun", \
                           "Microsoft\Ctf\LangBarAddin", \
                           "Microsoft\Internet Explorer\Explorer Bars", \
                           "Microsoft\Internet Explorer\Extensions", \
                           "Microsoft\Internet Explorer\Toolbar", \
                           "Microsoft\Windows CE Services\AutoStartOnConnect", \
                           "Microsoft\Windows CE Services\AutoStartOnDisconnect", \
                           "Microsoft\Windows NT\CurrentVersion\Drivers32", \
                           "Microsoft\Windows NT\CurrentVersion\Image File Execution Options", \
                           "Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Run", \
                           "Microsoft\Windows NT\CurrentVersion\Terminal Server\Install\Software\Microsoft\Windows\CurrentVersion\Runonce", \
                           "Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls", \
                           "Microsoft\Windows NT\CurrentVersion\Windows\IconServiceLib", \
                           "Microsoft\Windows NT\CurrentVersion\Winlogon\AppSetup", \
                           "Microsoft\Windows NT\CurrentVersion\Winlogon\Shell", \
                           "Microsoft\Windows NT\CurrentVersion\Winlogon\Taskman", \
                           "Microsoft\Windows NT\CurrentVersion\Winlogon\Userinit", \
                           "Microsoft\Windows NT\CurrentVersion\Winlogon\VmApplet", \
                           "Microsoft\Windows\CurrentVersion\Authentication\Credential Provider Filters", \
                           "Microsoft\Windows\CurrentVersion\Authentication\Credential Providers", \
                           "Microsoft\Windows\CurrentVersion\Authentication\PLAP Providers", \
                           "Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects", \
                           "Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler", \
                           "Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks", \
                           "Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers", \
                           "Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects", \
                           "Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Shutdown", \
                           "Microsoft\Windows\CurrentVersion\Group Policy\Scripts\Startup", \
                           "Microsoft\Windows\CurrentVersion\Policies\Explorer\Run", \
                           "Microsoft\Windows\CurrentVersion\Policies\System\Shell", \
                           "Microsoft\Windows\CurrentVersion\Run", \
                           "Microsoft\Windows\CurrentVersion\RunOnce", \
                           "Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad", \
                           "Policies\Microsoft\Windows\System\Scripts\Logoff", \
                           "Policies\Microsoft\Windows\System\Scripts\Logon", \
                           "Policies\Microsoft\Windows\System\Scripts\Shutdown", \
                           "Policies\Microsoft\Windows\System\Scripts\Startup", \
                           "Wow6432Node\Classes\*\ShellEx\ContextMenuHandlers", \
                           "Wow6432Node\Classes\*\ShellEx\PropertySheetHandlers", \
                           "Wow6432Node\Classes\AllFileSystemObjects\ShellEx\ContextMenuHandlers", \
                           "Wow6432Node\Classes\AllFileSystemObjects\ShellEx\DragDropHandlers", \
                           "Wow6432Node\Classes\AllFileSystemObjects\ShellEx\PropertySheetHandlers", \
                           "Wow6432Node\Classes\CLSID\{083863F1-70DE-11d0-BD40-00A0C911CE86}\Instance", \
                           "Wow6432Node\Classes\CLSID\{7ED96837-96F0-4812-B211-F13C24117ED3}\Instance", \
                           "Wow6432Node\Classes\CLSID\{ABE3B9A4-257D-4B97-BD1A-294AF496222E}\Instance", \
                           "Wow6432Node\Classes\CLSID\{AC757296-3522-4E11-9862-C17BE5A1767E}\Instance", \
                           "Wow6432Node\Classes\Directory\Background\ShellEx\ContextMenuHandlers", \
                           "Wow6432Node\Classes\Directory\ShellEx\ContextMenuHandlers", \
                           "Wow6432Node\Classes\Directory\Shellex\CopyHookHandlers", \
                           "Wow6432Node\Classes\Directory\Shellex\DragDropHandlers", \
                           "Wow6432Node\Classes\Directory\Shellex\PropertySheetHandlers", \
                           "Wow6432Node\Classes\Drive\ShellEx\ContextMenuHandlers", \
                           "Wow6432Node\Classes\Folder\Shellex\ColumnHandlers", \
                           "Wow6432Node\Classes\Folder\ShellEx\ContextMenuHandlers", \
                           "Wow6432Node\Classes\Folder\ShellEx\DragDropHandlers", \
                           "Wow6432Node\Classes\Folder\ShellEx\ExtShellFolderViews", \
                           "Wow6432Node\Classes\Folder\ShellEx\PropertySheetHandlers", \
                           "Wow6432Node\Microsoft\Active Setup\Installed Components", \
                           "Wow6432Node\Microsoft\Command Processor\Autorun", \
                           "Wow6432Node\Microsoft\Internet Explorer\Explorer Bars", \
                           "Wow6432Node\Microsoft\Internet Explorer\Extensions", \
                           "Wow6432Node\Microsoft\Internet Explorer\Toolbar", \
                           "Wow6432Node\Microsoft\Windows CE Services\AutoStartOnConnect", \
                           "Wow6432Node\Microsoft\Windows CE Services\AutoStartOnDisconnect", \
                           "Wow6432Node\Microsoft\Windows NT\CurrentVersion\Drivers32", \
                           "Wow6432Node\Microsoft\Windows NT\CurrentVersion\Image File Execution Options", \
                           "Wow6432Node\Microsoft\Windows NT\CurrentVersion\Windows\Appinit_Dlls", \
                           "Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\Browser Helper Objects", \
                           "Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\SharedTaskScheduler", \
                           "Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks", \
                           "Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellIconOverlayIdentifiers", \
                           "Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\ShellServiceObjects", \
                           "Wow6432Node\Microsoft\Windows\CurrentVersion\Run", \
                           "Wow6432Node\Microsoft\Windows\CurrentVersion\RunOnce", \
                           "Wow6432Node\Microsoft\Windows\CurrentVersion\ShellServiceObjectDelayLoad", \
                           "ControlSet001\Control\BootVerificationProgram\ImagePath", \
                           "ControlSet001\Control\Lsa\Authentication Packages", \
                           "ControlSet001\Control\Lsa\Notification Packages", \
                           "ControlSet001\Control\Lsa\OSConfig\Security Packages", \
                           "ControlSet001\Control\Lsa\Security Packages", \
                           "ControlSet001\Control\NetworkProvider\Order", \
                           "ControlSet001\Control\Print\Monitors", \
                           "ControlSet001\Control\SafeBoot\AlternateShell", \
                           "ControlSet001\Control\SecurityProviders\SecurityProviders", \
                           "ControlSet001\Control\ServiceControlManagerExtension", \
                           "ControlSet001\Control\Session Manager\AppCertDlls", \
                           "ControlSet001\Control\Session Manager\BootExecute", \
                           "ControlSet001\Control\Session Manager\Execute", \
                           "ControlSet001\Control\Session Manager\KnownDlls", \
                           "ControlSet001\Control\Session Manager\S0InitialCommand", \
                           "ControlSet001\Control\Session Manager\SetupExecute", \
                           "ControlSet001\Control\Terminal Server\Wds\rdpwd\StartupPrograms", \
                           "ControlSet001\Control\Terminal Server\WinStations\RDP-Tcp\InitialProgram", \
                           "ControlSet001\Services", \
                           "ControlSet001\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries", \
                           "ControlSet001\Services\WinSock2\Parameters\NameSpace_Catalog5\Catalog_Entries64", \
                           "ControlSet001\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries", \
                           "ControlSet001\Services\WinSock2\Parameters\Protocol_Catalog9\Catalog_Entries64", \
                           "Setup\CmdLine"]

command_line_filter = [
    r'.*iexplore.exe.*(scodef:)[0-9]*( credat:)[0-9]*( /prefetch:2)',
    r'.*chrome.exe.*',
    r'taskeng.exe ({)[0-9A-F\-]{36}(})',
    r'taskeng\.exe {\w{8}-\w{4}-\w{4}-\w{4}-\w{12}}',
    r'.*c:\\windows\\system32\\conhost.exe "[0-9\-]*',
    r'.*c:\\windows\\system32\\audiodg.exe "0x.{3}',
    r'.*Adobe\\Reader .*\\Reader\\AcroRd32\.exe.*',
]

# regex for filescan filter
filescan_filter = [
    r'\\Device\\\w*\\Windows\\Prefetch\\.*pf',
    r'\\Device\\\w*\\Windows\\SoftwareDistribution\\Download\\.*tmp',
    r'\\Device\\\w*\\Windows\\winsxs\\Temp\\.*_manifest',
    r'\\Device\\HarddiskVolumeShadowCopy.*'
]
