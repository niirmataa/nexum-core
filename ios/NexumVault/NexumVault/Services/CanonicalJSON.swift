import Foundation

enum CanonicalJSON {
    static func canonicalize(_ object: Any) throws -> String {
        let sorted = try sortKeys(object)
        let data = try JSONSerialization.data(withJSONObject: sorted, options: [])
        guard let string = String(data: data, encoding: .utf8) else {
            throw CanonicalJSONError.encodingFailed
        }
        return string
    }
    
    static func canonicalizeData(_ object: Any) throws -> Data {
        let sorted = try sortKeys(object)
        return try JSONSerialization.data(withJSONObject: sorted, options: [])
    }
    
    private static func sortKeys(_ object: Any) throws -> Any {
        if let dict = object as? [String: Any] {
            let sortedKeys = dict.keys.sorted()
            var result = [String: Any](minimumCapacity: sortedKeys.count)
            for key in sortedKeys {
                result[key] = try sortKeys(dict[key] as Any)
            }
            return result
        } else if let array = object as? [Any] {
            return try array.map { try sortKeys($0) }
        } else if object is NSNull {
            return object
        } else if object is String || object is NSNumber || object is Bool {
            return object
        } else {
            throw CanonicalJSONError.unsupportedType(String(describing: type(of: object)))
        }
    }
    
    static func canonicalize(_ jsonString: String) throws -> String {
        guard let data = jsonString.data(using: .utf8) else {
            throw CanonicalJSONError.invalidInput
        }
        let parsed = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
        return try canonicalize(parsed)
    }
    
    static func canonicalizeData(_ jsonString: String) throws -> Data {
        guard let data = jsonString.data(using: .utf8) else {
            throw CanonicalJSONError.invalidInput
        }
        let parsed = try JSONSerialization.jsonObject(with: data, options: [.fragmentsAllowed])
        return try canonicalizeData(parsed)
    }
}

enum CanonicalJSONError: Error, LocalizedError {
    case encodingFailed
    case unsupportedType(String)
    case invalidInput
    
    var errorDescription: String? {
        switch self {
        case .encodingFailed:
            return "Failed to encode canonical JSON to UTF-8"
        case .unsupportedType(let type):
            return "Unsupported JSON type: \(type)"
        case .invalidInput:
            return "Invalid JSON input string"
        }
    }
}
