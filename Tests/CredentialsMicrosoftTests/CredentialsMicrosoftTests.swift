import XCTest
@testable import CredentialsMicrosoft
import Kitura
import KituraNet
import Credentials
import KituraSession

struct MicrosoftPlist: Decodable {
    let token: String
}

final class CredentialsMicrosoftTests: XCTestCase {
    var router:Router!
    let credentials = Credentials()
    let microsoftCredentials = CredentialsMicrosoftToken(tokenTimeToLive: nil)
    let tokenTypeKey = "X-token-type"
    let accessTokenKey = "access_token"
    let authTokenType = "MicrosoftToken"
    let accessToken: String = CredentialsMicrosoftTests.getToken()
    
    static func getToken() -> String {
        // I know this is gross. Swift packages just don't have a good way to access resources right now. See https://stackoverflow.com/questions/47177036/use-resources-in-unit-tests-with-swift-package-manager
        let url = URL(fileURLWithPath: "/Users/chris/Desktop/Apps/SyncServerII/Private/CredentialsMicrosoft/token.plist")
        guard let data = try? Data(contentsOf: url) else {
            fatalError("Coul not get data from url")
        }

        let decoder = PropertyListDecoder()

        guard let microsoftToken = try? decoder.decode(MicrosoftPlist.self, from: data) else {
            fatalError("Coul not decode the plist")
        }

        return microsoftToken.token
    }
    
    override func setUp() {
        super.setUp()
        router = setupRouter()
    }
    
    func setupRouter() -> Router {
        let router = Router()
        
        router.all(middleware: KituraSession.Session(secret: "foobar"))
        credentials.register(plugin: microsoftCredentials)
        
        router.all { (request, response, next) in
            self.credentials.handle(request: request, response: response, next: next)
        }
        
        router.get("handler") { (request, response, next) in
            response.send("Done!")
        }

        return router
    }
    
    func testRequestFailsWithNoAuthHeader() {
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/handler", callback: { response in
                guard response?.httpStatusCode == .unauthorized else {
                    XCTFail("response?.httpStatusCode.rawValue: \(String(describing: response?.httpStatusCode.rawValue))")
                    expectation.fulfill()
                    return
                }
                expectation.fulfill()
            })
        }
    }
    
    func testRequestFailsWithBadAuthHeader() {
        let headers: [String: String] = [
            accessTokenKey: "foo",
            tokenTypeKey: authTokenType
        ]
        
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/handler", headers: headers, callback: { response in
                guard response?.httpStatusCode == .unauthorized else {
                    XCTFail("response?.httpStatusCode.rawValue: \(String(describing: response?.httpStatusCode.rawValue))")
                    expectation.fulfill()
                    return
                }
                expectation.fulfill()
            })
        }
    }
    
    func testRequestSucceedsWithValidAuthHeader() {
        let headers: [String: String] = [
            accessTokenKey: accessToken,
            tokenTypeKey: authTokenType
        ]
        
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/handler", headers: headers, callback: { response in
                guard response?.httpStatusCode == .OK else {
                    XCTFail("response?.httpStatusCode.rawValue: \(String(describing: response?.httpStatusCode.rawValue))")
                    expectation.fulfill()
                    return
                }
                expectation.fulfill()
            })
        }
    }
    
    func testHTTPRequest() {
        var requestOptions: [ClientRequest.Options] = []
        requestOptions.append(.schema("https://"))
        requestOptions.append(.hostname("graph.microsoft.com"))
        requestOptions.append(.method("GET"))
        requestOptions.append(.path("/v1.0/me"))

        var headers = [String:String]()
        headers["Authorization"] = "Bearer \(accessToken)"
        requestOptions.append(.headers(headers))

        let expectation = self.expectation(0)
        let req = HTTP.request(requestOptions) { response in
            guard let response = response, response.statusCode == HTTPStatusCode.OK else {
                XCTFail()
                expectation.fulfill()
                return
            }
            
            var data = Data()
            do {
                let size = try response.read(into: &data)
                print("size of data: \(size)")
                
                let dictionary = try JSONSerialization.jsonObject(with: data, options: []) as? [String : Any]
                print("dictionary: \(String(describing: dictionary))")
            } catch let error {
                XCTFail("\(error)")
            }

            expectation.fulfill()
        }
        req.end()
        waitForExpectations(timeout: 10, handler: nil)
    }
    
    func testCredentialsDirectly() {
        let expectation = self.expectation(0)
        microsoftCredentials.doRequest(token: accessToken, options: [:], onSuccess: { userProfile in
            expectation.fulfill()
        }, onFailure: { httpStatus in
            XCTFail("httpStatus: \(String(describing: httpStatus))")
            expectation.fulfill()
        })
        waitForExpectations(timeout: 10, handler: nil)
    }

    // Tests that when a request to a Codable route that includes this middleware does not
    // contain the matching X-token-type header, the middleware skips authentication and a
    // second handler is instead invoked.
    func testMissingTokenType() {
        let headers: [String: String] = [
            accessTokenKey: accessToken,
        ]
        
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/handler", headers: headers, callback: { response in
                guard response?.httpStatusCode == .unauthorized else {
                    XCTFail("response?.httpStatusCode.rawValue: \(String(describing: response?.httpStatusCode.rawValue))")
                    expectation.fulfill()
                    return
                }
                expectation.fulfill()
            })
        }
    }

    // Tests that when a request to a Codable route that includes this middleware contains
    // the matching X-token-type header, but does not supply an access_token, the middleware
    // fails authentication and returns unauthorized.
    func testMissingAccessToken() {
        let headers: [String: String] = [
            tokenTypeKey: authTokenType
        ]
        
        performServerTest(router: router) { expectation in
            self.performRequest(method: "get", path: "/handler", headers: headers, callback: { response in
                guard response?.httpStatusCode == .unauthorized else {
                    XCTFail("response?.httpStatusCode.rawValue: \(String(describing: response?.httpStatusCode.rawValue))")
                    expectation.fulfill()
                    return
                }
                expectation.fulfill()
            })
        }
    }

    static var allTests = [
        ("testRequestFailsWithNoAuthHeader", testRequestFailsWithNoAuthHeader),
        ("testRequestFailsWithBadAuthHeader", testRequestFailsWithBadAuthHeader),
        ("testRequestSucceedsWithValidAuthHeader", testRequestSucceedsWithValidAuthHeader),
        ("testHTTPRequest", testHTTPRequest),
        ("testCredentialsDirectly", testCredentialsDirectly),
        ("testMissingTokenType", testMissingTokenType),
        ("testMissingAccessToken", testMissingAccessToken)
    ]
}
