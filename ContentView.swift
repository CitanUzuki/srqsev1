import SwiftUI

struct LoginView: View {
    @State private var email = ""
    @State private var password = ""
    @State private var errorMessage = ""

    var body: some View {
        VStack {
            TextField("Email", text: $email)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .padding()

            SecureField("Password", text: $password)
                .textFieldStyle(RoundedBorderTextFieldStyle())
                .padding()

            Button("Log In") {
                if let postData = createLoginIMAPParametersWithEncryptedString(email: email, plainPassword: password) {
                    sendLoginRequest(postData: postData)
                } else {
                    errorMessage = "Error creating login parameters."
                }
            }
            .padding()

            if !errorMessage.isEmpty {
                Text(errorMessage)
                    .foregroundColor(.red)
            }
        }
        .padding()
    }

    func sendLoginRequest(postData: Data) {
        guard let url = URL(string: "https://backend.mydigitalmind.ai/login-imap") else {
            print("Invalid URL")
            return
        }
        var request = URLRequest(url: url, timeoutInterval: Double.infinity)
        request.addValue("application/json", forHTTPHeaderField: "Content-Type")
        request.httpMethod = "POST"
        request.httpBody = postData

        URLSession.shared.dataTask(with: request) { data, response, error in
            if let error = error {
                print("Request Error: \(error)")
                return
            }
            guard let data = data else {
                print("No data received")
                return
            }
            if let responseString = String(data: data, encoding: .utf8) {
                print("Server Response: \(responseString)")
                // Here you can handle the server response (e.g., save session token)
            }
        }.resume()
    }
}

struct LoginView_Previews: PreviewProvider {
    static var previews: some View {
        LoginView()
    }
}

import CryptoKit
import Foundation

func encryptPasswordAESGCM(password: String, secretKey: String = "MDM_S3CR3T_K3Y-1") -> String? {
    guard let passwordData = password.data(using: .utf8),
          let keyData = secretKey.data(using: .utf8) else {
        print("Error converting password or key to Data.")
        return nil
    }

    let symmetricKey = SymmetricKey(data: keyData)

    do {
        let nonce = try AES.GCM.Nonce(data: Data(count: 12))
        let sealedBox = try AES.GCM.seal(passwordData, using: symmetricKey, nonce: nonce)

        let ciphertext = sealedBox.ciphertext
        let tag = sealedBox.tag
        let ivData = sealedBox.nonce

        // Convert Nonce to Data before base64 encoding
        let ivBase64 = Data(ivData).base64EncodedString()
        let dataBase64 = ciphertext.base64EncodedString()
        let tagBase64 = tag.base64EncodedString()

        // Create the JSON string directly
        let jsonString = #"{"iv":"\#(ivBase64)","data":"\#(dataBase64)","tag":"\#(tagBase64)"}"#
        return jsonString
    } catch {
        print("Error encrypting the password: \(error)")
        return nil
    }
}

func createLoginIMAPParametersWithEncryptedString(email: String, plainPassword: String, hostImap: String = "imap.rockyour.cloud", hostSmtp: String = "smtp.rockyour.cloud") -> Data? {
    if let encryptedPasswordString = encryptPasswordAESGCM(password: plainPassword) {
        do {
            let parameters: [String: Any] = [
                "hostImap": hostImap,
                "hostSmtp": hostSmtp,
                "email": email,
                "password": encryptedPasswordString // The encrypted JSON string
            ]

            // Convert the dictionary to Data (JSON)
            return try JSONSerialization.data(withJSONObject: parameters, options: [])
        } catch {
            print("Error serializing parameters to JSON: \(error)")
            return nil
        }
    } else {
        print("Error encrypting the password.")
        return nil
    }
}
