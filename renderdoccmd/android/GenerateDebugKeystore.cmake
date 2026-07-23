if(EXISTS "${KEYSTORE}")
    return()
endif()

execute_process(
    COMMAND "${KEYTOOL}"
            -genkey
            -keystore "${KEYSTORE}"
            -storepass android
            -alias rdocandroidkey
            -keypass android
            -keyalg RSA
            -keysize 2048
            -validity 10000
            -dname "CN=, OU=, O=, L=, S=, C="
    RESULT_VARIABLE KEYTOOL_RESULT
)

if(NOT KEYTOOL_RESULT EQUAL 0)
    message(FATAL_ERROR "Failed to generate Android debug keystore: ${KEYTOOL_RESULT}")
endif()
