// Adapted from https://github.com/IBM-Swift/Kitura-CredentialsGoogle

import Kitura
import KituraNet
import LoggerAPI
import Credentials
import HeliumLogger
import SwiftJWT
import Foundation
import LoggerAPI

/// Authentication using Microsoft OAuth2 token.
public class CredentialsMicrosoftToken: CredentialsPluginProtocol, CredentialsTokenTTL {

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
    
    private let tokenTypeKey = "X-token-type"
    
    // What iOS MSAL calls the idToken; a OAuth2 JWT token.
    private let accessTokenKey = "access_token"
    
    // What iOS MSAL calls the accessToken
    // See https://docs.microsoft.com/en-us/azure/active-directory/develop/id-tokens
    private let microsoftAccessTokenKey = "X-microsoft-access-token"
    
    private var expectedUserIdentifier: String!
    
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
        
        // For token type differences, see (https://github.com/AzureAD/microsoft-authentication-library-for-objc/issues/683)
        // My question seems related to (https://github.com/AzureAD/azure-activedirectory-library-for-js/issues/693)
        
        guard let type = request.headers[tokenTypeKey], type == name else {
            onPass(nil, nil)
            return
        }
        
        // The microsoftAccessTokenKey token is needed for authentication.
        guard let token = request.headers[microsoftAccessTokenKey] else {
            onFailure(nil, nil)
            return
        }
        
        // The accessTokenKey token is needed for further server API access
        guard let accessToken = request.headers[accessTokenKey] else {
            onFailure(nil, nil)
            return
        }

        expectedUserIdentifier = MicrosoftClaims.getUserIdentifier(idToken: accessToken)
        
        if expectedUserIdentifier == nil  {
            onFailure(nil, nil)
            return
        }

        getProfileAndCacheIfNeeded(token: token, options: options, onSuccess: onSuccess, onFailure: onFailure)
    }
    
    enum FailureResult: Swift.Error {
        case badResponse
        case statusCode(HTTPStatusCode)
        case failedSerialization
        case failedCreatingProfile
        case failedGettingBodyData
        case couldNotGetSelf
    }
    
    // This method is called by getProfileAndCacheIfNeeded, when needed.
    public func generateNewProfile(token: String, options: [String : Any], completion: @escaping (CredentialsTokenTTLResult) -> Void) {
        // See https://docs.microsoft.com/en-us/graph/api/user-get?view=graph-rest-1.0&tabs=http
        var requestOptions: [ClientRequest.Options] = []
        requestOptions.append(.schema("https://"))
        requestOptions.append(.hostname("graph.microsoft.com"))
        requestOptions.append(.method("GET"))
        requestOptions.append(.path("/v1.0/me"))

        var headers = [String:String]()
        headers["Authorization"] = "Bearer \(token)"
        requestOptions.append(.headers(headers))

        let req = HTTP.request(requestOptions) {[weak self] response in
            guard let self = self else {
                completion(.error(FailureResult.couldNotGetSelf))
                return
            }

            guard let response = response else {
                completion(.error(FailureResult.badResponse))
                return
            }
            
            var body = Data()
            do {
                try response.readAllData(into: &body)
            } catch let error {
                Log.debug("\(error)")
                completion(.error(FailureResult.failedGettingBodyData))
                return
            }
            
            guard let stringBody = String(data: body, encoding: .utf8) else {
                completion(.error(FailureResult.failedGettingBodyData))
                return
            }
            
            Log.debug("stringBody: \(String(describing: stringBody))")
            
            guard response.statusCode == HTTPStatusCode.OK else {
                completion(.error(FailureResult.statusCode(response.statusCode)))
                return
            }

            guard let dictionary = try? JSONSerialization.jsonObject(with: body, options: []) as? [String : Any] else {
                Log.error("Failed to serialize body data")
                completion(.error(FailureResult.failedSerialization))
                return
            }
            
            guard let userProfile = createUserProfile(from: dictionary, for: self.name) else {
                Log.error("Failed to create user profile")
                completion(.error(FailureResult.failedCreatingProfile))
                return
            }
            
            // Need to make sure the two tokens refer to the same user
            guard self.expectedUserIdentifier == userProfile.id else {
                Log.error("Expected identifier wasn't the same as the profile identifier")
                completion(.error(FailureResult.failedCreatingProfile))
                return
            }
        
            if let delegate = self.delegate ?? options[CredentialsMicrosoftOptions.userProfileDelegate] as? UserProfileDelegate {
                delegate.update(userProfile: userProfile, from: dictionary)
            }

            completion(.success(userProfile))
        }
        
        // print("URL: \(req.url)")
        req.end()
    }
}
