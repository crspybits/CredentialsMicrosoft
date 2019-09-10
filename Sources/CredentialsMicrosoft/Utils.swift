// Adapted from https://github.com/IBM-Swift/Kitura-CredentialsGoogle

import Credentials


/* Example:
{
    "@odata.context": "https://graph.microsoft.com/v1.0/$metadata#users/$entity",
    "displayName": "Chris Prince",
    "surname": "Prince",
    "givenName": "Chris",
    "id": "<snip>",
    "userPrincipalName": "chris@cprince.com",
    "businessPhones": [],
    "jobTitle": null,
    "mail": null,
    "mobilePhone": null,
    "officeLocation": null,
    "preferredLanguage": null
}
*/
func createUserProfile(from microsoftData: [String:Any], for provider: String) -> UserProfile? {
    guard let id = microsoftData["id"] as? String else {
        return nil
    }
    
    var userEmails: [UserProfile.UserProfileEmail]? = nil
    if let email = microsoftData["userPrincipalName"] as? String {
        let userEmail = UserProfile.UserProfileEmail(value: email, type: "")
        userEmails = [userEmail]
    }
    
    let displayName = microsoftData["displayName"] as? String
    let surname = microsoftData["surname"] as? String
    let givenName = microsoftData["givenName"] as? String

    let userName = UserProfile.UserProfileName(
        familyName: surname ?? "",
        givenName: givenName ?? "",
        middleName: "")
    
    return UserProfile(id: id, displayName: displayName ?? "", provider: provider, name: userName, emails: userEmails, photos: nil)
}

/* Example:
{
    "account_id": "dbid:AAH4f99T0taONIb-OurWxbNQ6ywGRopQngc",
    "name": {
        "given_name": "Franz",
        "surname": "Ferdinand",
        "familiar_name": "Franz",
        "display_name": "Franz Ferdinand (Personal)",
        "abbreviated_name": "FF"
    },
    "email": "franz@dropbox.com",
    "email_verified": true,
    "disabled": false,
    "is_teammate": false,
    "profile_photo_url": "https://dl-web.dropbox.com/account_photo/get/dbid%3AAAH4f99T0taONIb-OurWxbNQ6ywGRopQngc?vers=1453416696524\u0026size=128x128"
}
*/
