//
//  SwiftUIView.swift
//  
//
//  Created by Christopher Guirguis on 12/27/21.
//

import SwiftUI
import GoogleSignIn
import FBSDKLoginKit
import Firebase
import FirebaseAuth
import CryptoKit
import AuthenticationServices


fileprivate var provider = OAuthProvider(providerID: "twitter.com")

public extension FirebaseAuthHelper {
  func twitterAuth() {
    provider.getCredentialWith(nil) { credential, error in
      if let credential = credential, error == nil {
        self.firebaseAuth(credentials: credential)
      } else {
        self.setLoggingIn(false)
        self.loginErrorAction?("Twitter")
        return
      }
    }
  }
}
