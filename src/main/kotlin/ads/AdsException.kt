package ads

class AdsException(val errorCode: AdsErrorCode, message: String) : Exception(message)
