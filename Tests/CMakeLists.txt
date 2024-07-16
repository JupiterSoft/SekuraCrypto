find_package(QT NAMES ${QTVERSION} REQUIRED COMPONENTS Core Widgets Network Gui
                                                       Test Qml)
find_package(Qt${QT_VERSION_MAJOR} REQUIRED COMPONENTS Core Widgets Network Gui
                                                       Test Qml)

enable_testing()

set(TEST_NAME TestCrypto)

include_directories(../../LibCom)

function(SETUP_TESTS)
  foreach(_testname ${ARGN})
    add_executable(${TEST_NAME}_${_testname} tst_${_testname}.cpp)
    add_test(NAME ${TEST_NAME}_${_testname} COMMAND ${TEST_NAME}_${_testname})
    target_link_libraries(
      ${TEST_NAME}_${_testname}
      Qt${QT_MAJOR_VERISION}::Test
      Qt${QT_VERSION_MAJOR}::Core
      Qt${QT_VERSION_MAJOR}::Network
      Qt${QT_VERSION_MAJOR}::Widgets
      Qt${QT_VERSION_MAJOR}::Gui
      Qt${QT_VERSION_MAJOR}::Qml
      Crypto
      Com)
  endforeach()
endfunction()

setup_tests(secp256k1)
