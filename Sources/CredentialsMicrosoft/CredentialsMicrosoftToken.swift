// Adapted from https://github.com/IBM-Swift/Kitura-CredentialsGoogle

import Kitura
import KituraNet
import LoggerAPI
import Credentials

import Foundation

/// Protocol to make it easier to add token TLL to credentials plugins.
public protocol CredentialsTokenTLL {
    var usersCache: NSCache<NSString, BaseCacheElement>? {get}
    var tokenTimeToLive: TimeInterval? {get}
}

extension CredentialsTokenTLL {
    /// Returns true iff the token/UserProfile was found in the cache and onSuccess was called.
    ///
    /// - Parameter token: The Oauth2 token, used as a key in the cache.
    /// - Parameter onSuccess: The callback used in the authenticate method.
    ///
    func useTokenInCache(token: String, onSuccess: @escaping (UserProfile) -> Void) -> Bool {
        #if os(Linux)
            let key = NSString(string: token)
        #else
            let key = token as NSString
        #endif
        
        if let cached = usersCache?.object(forKey: key) {
            if let ttl = tokenTimeToLive {
                if Date() < cached.createdAt.addingTimeInterval(ttl) {
                    onSuccess(cached.userProfile)
                    return true
                }
                // If current time is later than time to live, continue to standard token authentication.
                // Don't need to evict token, since it will replaced if the token is successfully autheticated.
            } else {
                // No time to live set, use token until it is evicted from the cache
                onSuccess(cached.userProfile)
                return true
            }
        }
        
        return false
    }
}

/// Authentication using Microsoft OAuth2 token.
public class CredentialsMicrosoftToken: CredentialsPluginProtocol, CredentialsTokenTLL {
    /// The name of the plugin.
    public var name: String {
        return "MicrosoftToken"
    }
    
    /// An indication as to whether the plugin is redirecting or not.
    public var redirecting: Bool {
        return false
    }
    
    /// The time in seconds since the user profile was generated that the access token will be considered valid.
    public let tokenTimeToLive: TimeInterval?

    private var delegate: UserProfileDelegate?
    
    /// A delegate for `UserProfile` manipulation.
    public var userProfileDelegate: UserProfileDelegate? {
        return delegate
    }
    
    /// Initialize a `CredentialsMicrosoftToken` instance.
    ///
    /// - Parameter options: A dictionary of plugin specific options. The keys are defined in `CredentialsOwnCloudOptions`.
    /// - Parameter tokenTimeToLive: The time in seconds since the user profile was generated that the access token will be considered valid.
    public init(options: [String:Any]?=nil, tokenTimeToLive: TimeInterval? = nil) {
        delegate = options?[CredentialsMicrosoftOptions.userProfileDelegate] as? UserProfileDelegate
        self.tokenTimeToLive = tokenTimeToLive
    }
    
    /// User profile cache.
    public var usersCache: NSCache<NSString, BaseCacheElement>?
    
    /// Authenticate incoming request using Microsoft OAuth2 token.
    ///
    /// - Parameter request: The `RouterRequest` object used to get information
    ///                     about the request.
    /// - Parameter response: The `RouterResponse` object used to respond to the
    ///                       request.
    /// - Parameter options: The dictionary of plugin specific options.
    /// - Parameter onSuccess: The closure to invoke in the case of successful authentication.
    /// - Parameter onFailure: The closure to invoke in the case of an authentication failure.
    /// - Parameter onPass: The closure to invoke when the plugin doesn't recognize the
    ///                     authentication token in the request.
    /// - Parameter inProgress: The closure to invoke to cause a redirect to the login page in the
    ///                     case of redirecting authentication.
    public func authenticate(request: RouterRequest, response: RouterResponse,
                             options: [String:Any], onSuccess: @escaping (UserProfile) -> Void,
                             onFailure: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                             onPass: @escaping (HTTPStatusCode?, [String:String]?) -> Void,
                             inProgress: @escaping () -> Void) {
        if let type = request.headers["X-token-type"], type == name {
            if let token = request.headers["access_token"] {
                if useTokenInCache(token: token, onSuccess: onSuccess) {
                    return
                }
                
                doRequest(token: token, options: options, onSuccess: onSuccess, onFailure: { _ in
                    onFailure(nil, nil)
                })
            }
            else {
                onFailure(nil, nil)
            }
        }
        else {
            onPass(nil, nil)
        }
    }
    
    enum FailureResult: Swift.Error {
        case badResponse
        case statusCode(HTTPStatusCode)
        case failedSerialization
        case failedCreatingProfile
    }
    
    func doRequest(token: String, options: [String:Any],
        onSuccess: @escaping (UserProfile) -> Void,
        onFailure: @escaping (Swift.Error) -> Void) {
       // See https://docs.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0&tabs=http

        var requestOptions: [ClientRequest.Options] = []
        requestOptions.append(.schema("https://"))
        requestOptions.append(.hostname("graph.microsoft.com"))
        requestOptions.append(.method("GET"))
        requestOptions.append(.path("/v1.0/me"))

        var headers = [String:String]()
        headers["Authorization"] = "Bearer \(token)"
        requestOptions.append(.headers(headers))

        let req = HTTP.request(requestOptions) { response in
            guard let response = response, response.statusCode == HTTPStatusCode.OK else {
                onFailure(FailureResult.badResponse)
                return
            }
            
            do {
                var body = Data()
                try response.readAllData(into: &body)
                
                let stringBody = String(data: body, encoding: .utf8)
                print("stringBody: \(String(describing: stringBody))")
                
                guard let dictionary = try JSONSerialization.jsonObject(with: body, options: []) as? [String : Any] else {
                    Log.error("Failed to serialize body data")
                    onFailure(FailureResult.failedSerialization)
                    return
                }
            
                guard let userProfile = createUserProfile(from: dictionary, for: self.name) else {
                    Log.error("Failed to create user profile")
                    onFailure(FailureResult.failedCreatingProfile)
                    return
                }
            
                if let delegate = self.delegate ?? options[CredentialsMicrosoftOptions.userProfileDelegate] as? UserProfileDelegate {
                    delegate.update(userProfile: userProfile, from: dictionary)
                }

                let newCacheElement = BaseCacheElement(profile: userProfile)
                #if os(Linux)
                    let key = NSString(string: token)
                #else
                    let key = token as NSString
                #endif
                
                self.usersCache!.setObject(newCacheElement, forKey: key)
                onSuccess(userProfile)
                
            } catch {
                Log.error("Failed to read Microsoft response")
                onFailure(FailureResult.statusCode(response.statusCode))
            }
        }
        
        print("URL: \(req.url)")
        req.end()
    }
}
