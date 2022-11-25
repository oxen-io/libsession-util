local docker_base = 'registry.oxen.rocks/lokinet-ci-';

local submodule_commands = [
  'git fetch --tags',
  'git submodule update --init --recursive --depth=1 --jobs=4',
];
local submodules = {
  name: 'submodules',
  image: 'drone/git',
  commands: submodule_commands,
};

local apt_get_quiet = 'apt-get -o=Dpkg::Use-Pty=0 -q';

local default_deps_nocxx = [];
local default_deps = ['g++'] + default_deps_nocxx;

local docker_base = 'registry.oxen.rocks/lokinet-ci-';

// Regular build on a debian-like system:
local debian_pipeline(name,
                      image,
                      arch='amd64',
                      deps=default_deps,
                      build_type='Release',
                      lto=false,
                      werror=true,
                      cmake_extra='',
                      jobs=6,
                      tests=true,
                      oxen_repo=false,
                      kitware_repo=''/* ubuntu codename, if wanted */,
                      allow_fail=false) = {
  kind: 'pipeline',
  type: 'docker',
  name: name,
  platform: { arch: arch },
  steps: [
    submodules,
    {
      name: 'build',
      image: image,
      pull: 'always',
      [if allow_fail then 'failure']: 'ignore',
      commands: [
        'echo "Building on ${DRONE_STAGE_MACHINE}"',
        'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
        apt_get_quiet + ' update',
        apt_get_quiet + ' install -y eatmydata',
      ] + (
        if oxen_repo then [
          'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y lsb-release',
          'cp contrib/deb.oxen.io.gpg /etc/apt/trusted.gpg.d',
          'echo deb http://deb.oxen.io $$(lsb_release -sc) main >/etc/apt/sources.list.d/oxen.list',
          'eatmydata ' + apt_get_quiet + ' update',
        ] else []
      ) + (
        if kitware_repo != '' then [
          'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y curl ca-certificates',
          'curl -sS https://apt.kitware.com/keys/kitware-archive-latest.asc | gpg --dearmor - >/usr/share/keyrings/kitware-archive-keyring.gpg',
          'echo "deb [signed-by=/usr/share/keyrings/kitware-archive-keyring.gpg] https://apt.kitware.com/ubuntu/ ' + kitware_repo + ' main" >/etc/apt/sources.list.d/kitware.list',
          'eatmydata ' + apt_get_quiet + ' update',
        ] else []
      ) + [
        'eatmydata ' + apt_get_quiet + ' dist-upgrade -y',
        'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y cmake make git ccache ' + std.join(' ', deps),
        'mkdir build',
        'cd build',
        'cmake .. -DCMAKE_CXX_FLAGS=-fdiagnostics-color=always -DCMAKE_BUILD_TYPE=' + build_type + ' ' +
        (if werror then '-DWARNINGS_AS_ERRORS=ON ' else '') +
        '-DUSE_LTO=' + (if lto then 'ON ' else 'OFF ') +
        '-DWITH_TESTS=' + (if tests then 'ON ' else 'OFF ') +
        cmake_extra,
        'VERBOSE=1 make -j' + jobs,
      ],
    },
  ] + (if tests then
         [{
           name: 'tests',
           image: image,
           pull: 'always',
           [if allow_fail then 'failure']: 'ignore',
           commands: [
             'cd build',
             './tests/testAll --colour-mode ansi',
           ],
         }] else []),
};
// windows cross compile on debian
local windows_cross_pipeline(name,
                             image,
                             arch='amd64',
                             build_type='Release',
                             lto=false,
                             werror=false,
                             cmake_extra='',
                             toolchain='windows-x64',
                             jobs=6,
                             tests=true,
                             allow_fail=false) = {
  kind: 'pipeline',
  type: 'docker',
  name: name,
  platform: { arch: arch },
  steps: [
    submodules,
    {
      name: 'build',
      image: image,
      pull: 'always',
      [if allow_fail then 'failure']: 'ignore',
      environment: { SSH_KEY: { from_secret: 'SSH_KEY' }, WINDOWS_BUILD_NAME: toolchain + 'bit' },
      commands: [
        'echo "Building on ${DRONE_STAGE_MACHINE}"',
        'echo "man-db man-db/auto-update boolean false" | debconf-set-selections',
        apt_get_quiet + ' update',
        apt_get_quiet + ' install -y eatmydata',
        'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y cmake git ccache g++-mingw-w64-x86-64-posix',
        'mkdir build',
        'cd build',
        'cmake .. -DCMAKE_CXX_FLAGS=-fdiagnostics-color=always -DCMAKE_BUILD_TYPE=' + build_type + ' ' +
        (if werror then '-DWARNINGS_AS_ERRORS=ON ' else '') +
        '-DUSE_LTO=' + (if lto then 'ON ' else 'OFF ') +
        '-DWITH_TESTS=' + (if tests then 'ON ' else 'OFF ') +
        '-DCMAKE_TOOLCHAIN_FILE=../cmake/' + toolchain + '-toolchain.cmake ' +
        cmake_extra,
        'VERBOSE=1 make -j' + jobs,
      ],
    },
  ] + (if tests then
         [{
           name: 'tests',
           image: image,
           pull: 'always',
           [if allow_fail then 'failure']: 'ignore',
           environment: { WINEDEBUG: '-all' },
           commands: [
             apt_get_quiet + ' install -y --no-install-recommends wine64',
             'cd build',
             'wine64-stable ./tests/testAll.exe --colour-mode ansi',
           ],
         }] else []),
};

local clang(version) = debian_pipeline(
  'Debian sid/clang-' + version + ' (amd64)',
  docker_base + 'debian-sid-clang',
  deps=['clang-' + version] + default_deps_nocxx,
  cmake_extra='-DCMAKE_C_COMPILER=clang-' + version + ' -DCMAKE_CXX_COMPILER=clang++-' + version + ' '
);

local full_llvm(version) = debian_pipeline(
  'Debian sid/llvm-' + version + ' (amd64)',
  docker_base + 'debian-sid-clang',
  deps=['clang-' + version, ' lld-' + version, ' libc++-' + version + '-dev', 'libc++abi-' + version + '-dev']
       + default_deps_nocxx,
  cmake_extra='-DCMAKE_C_COMPILER=clang-' + version +
              ' -DCMAKE_CXX_COMPILER=clang++-' + version +
              ' -DCMAKE_CXX_FLAGS="-stdlib=libc++ -fcolor-diagnostics" ' +
              std.join(' ', [
                '-DCMAKE_' + type + '_LINKER_FLAGS=-fuse-ld=lld-' + version
                for type in ['EXE', 'MODULE', 'SHARED']
              ])
);

// Macos build
local mac_builder(name,
                  build_type='Release',
                  werror=true,
                  lto=false,
                  cmake_extra='',
                  extra_cmds=[],
                  jobs=6,
                  tests=true,
                  allow_fail=false) = {
  kind: 'pipeline',
  type: 'exec',
  name: name,
  platform: { os: 'darwin', arch: 'amd64' },
  steps: [
    { name: 'submodules', commands: submodule_commands },
    {
      name: 'build',
      environment: { SSH_KEY: { from_secret: 'SSH_KEY' } },
      commands: [
        'echo "Building on ${DRONE_STAGE_MACHINE}"',
        // If you don't do this then the C compiler doesn't have an include path containing
        // basic system headers.  WTF apple:
        'export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"',
        'mkdir build',
        'cd build',
        'cmake .. -DCMAKE_CXX_FLAGS=-fcolor-diagnostics -DCMAKE_BUILD_TYPE=' + build_type + ' ' +
        (if werror then '-DWARNINGS_AS_ERRORS=ON ' else '') +
        '-DUSE_LTO=' + (if lto then 'ON ' else 'OFF ') +
        '-DWITH_TESTS=' + (if tests then 'ON ' else 'OFF ') +
        cmake_extra,
        'VERBOSE=1 make -j' + jobs,
      ],
    },
  ] + (if tests then
         [{
           name: 'tests',
           [if allow_fail then 'failure']: 'ignore',
           commands: [
             'cd build',
             './tests/testAll --colour-mode ansi',
           ],
         }] else []),
};

[
  {
    name: 'lint check',
    kind: 'pipeline',
    type: 'docker',
    steps: [{
      name: 'build',
      image: docker_base + 'lint',
      pull: 'always',
      commands: [
        'echo "Building on ${DRONE_STAGE_MACHINE}"',
        apt_get_quiet + ' update',
        apt_get_quiet + ' install -y eatmydata',
        'eatmydata ' + apt_get_quiet + ' install --no-install-recommends -y git clang-format-14 jsonnet',
        './contrib/ci/drone-format-verify.sh',
      ],
    }],
  },

  // Various debian builds
  debian_pipeline('Debian sid (amd64)', docker_base + 'debian-sid'),
  debian_pipeline('Debian sid/Debug (amd64)', docker_base + 'debian-sid', build_type='Debug'),
  clang(14),
  full_llvm(14),
  debian_pipeline('Debian stable (i386)', docker_base + 'debian-stable/i386'),
  debian_pipeline('Debian buster (amd64)', docker_base + 'debian-buster'),
  debian_pipeline('Ubuntu latest (amd64)', docker_base + 'ubuntu-rolling'),
  debian_pipeline('Ubuntu LTS (amd64)', docker_base + 'ubuntu-lts'),
  debian_pipeline('Ubuntu bionic (amd64)',
                  docker_base + 'ubuntu-bionic',
                  deps=['g++-8'] + default_deps_nocxx,
                  kitware_repo='bionic',
                  cmake_extra='-DCMAKE_C_COMPILER=gcc-8 -DCMAKE_CXX_COMPILER=g++-8'),

  // ARM builds (ARM64 and armhf)
  debian_pipeline('Debian sid (ARM64)', docker_base + 'debian-sid', arch='arm64', jobs=4),
  debian_pipeline('Debian stable (armhf)', docker_base + 'debian-stable/arm32v7', arch='arm64', jobs=4),

  // Windows builds (x64)
  windows_cross_pipeline('Windows (amd64)', docker_base + 'debian-win32-cross'),

  // Macos builds:
  mac_builder('macOS (Release)'),
  mac_builder('macOS (Debug)', build_type='Debug'),

  // iOS static lib build
  {
    kind: 'pipeline',
    type: 'exec',
    name: 'iOS static lib',
    platform: { os: 'darwin', arch: 'amd64' },
    steps: [
      { name: 'submodules', commands: submodule_commands },
      {
        name: 'build',
        environment: { SSH_KEY: { from_secret: 'SSH_KEY' } },
        commands: [
          'echo "Building on ${DRONE_STAGE_MACHINE}"',
          // If you don't do this then the C compiler doesn't have an include path containing
          // basic system headers.  WTF apple:
          'export SDKROOT="$(xcrun --sdk macosx --show-sdk-path)"',
          'export JOBS=6',
          './contrib/ios.sh',
          'cd build-ios && ../contrib/ci/drone-static-upload.sh',
        ],
      },
    ],
  },
]
