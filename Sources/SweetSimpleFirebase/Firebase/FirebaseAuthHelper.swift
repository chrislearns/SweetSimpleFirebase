//
//  FirebaseAuthHelper.swift
//  
//
//  Created by Christopher Guirguis on 12/26/21.
//

#if os(iOS)
import SwiftUI
import FBSDKLoginKit
import GoogleSignIn
import Firebase
import CryptoKit
import AuthenticationServices

open class FirebaseAuthHelper: ObservableObject {
  public static let shared = FirebaseAuthHelper(clearUserData: nil)
  
  public init(clearUserData: (() -> ())? = nil,
              loginErrorAction: ((_ provider: String) -> ())? = nil){
    self.clearUserData = clearUserData
    self.loginErrorAction = loginErrorAction
  }
  @Published public private(set) var signInState: SignInState = .signedOut
  @Published public var isLoggingIn = false
  
  public func setSignInState(_ newState: SignInState) {
    if self.signInState != newState {
      self.signInState = newState
    }
  }
  
  public func updateLoginState() {
    switch Auth.auth().currentUser {
    case .none:
      self.setSignInState(.signedOut)
    case .some(_):
      self.setSignInState(.signedIn)
      
    }
  }
  
  public var loginErrorAction: ((_ provider: String) -> ())? = nil
  public var clearUserData: (() -> ())? = nil
  
  public func setLoggingIn(_ bool: Bool){
    withAnimation {
      self.isLoggingIn = bool
    }
  }
  
}

public extension FirebaseAuthHelper {
  func firebasePasswordSignup(email: String, password: String, firstName: String, lastName: String, completion: @escaping ((User?, Error?) -> ())){
      Auth.auth().createUser(withEmail: email, password: password) { authDataResults, error in
          guard let authDataResults = authDataResults, error == nil else {
              print(error?.localizedDescription as Any)
              completion(nil, error)
            
              return
          }
          
          
          self.signInState = .signedIn
          print("logged in as \(authDataResults.user.displayName ?? "(uid):\(authDataResults.user.uid)")")
          
          self.firebaseChangeName("\(firstName) \(lastName)", completion: {user, error in
              completion(authDataResults.user, error)
          })
          
      }
  }

  func firebasePasswordSignIn(email: String, password: String, completion: @escaping ((User?, Error?) -> ())){
      Auth.auth().signIn(withEmail: email, password: password) { authDataResults, error in
          guard let authDataResults = authDataResults, error == nil else {
              print(error?.localizedDescription as Any)
              completion(nil, error)
              return
          }
          
          self.signInState = .signedIn
          completion(authDataResults.user, error)
      }
  }
  func firebaseSignOut(completion: (Error?) -> ()){
      do {
          try Auth.auth().signOut()
          self.signInState = .signedOut
        self.clearUserData?()
          completion(nil)
      } catch {
          completion(NSError())
      }
      
  }
  
  func firebaseDeleteUser(completion: @escaping (Error?) -> ()){
      let user = Auth.auth().currentUser
      
      user?.delete { error in
        if Auth.auth().currentUser == nil {
          self.signInState = .signedOut
        }
          completion(error)
      }
  }
  
  func firebaseChangeName(_ displayName: String, completion: ((User?, Error?) -> ())?){
      guard let changeRequest = Auth.auth().currentUser?.createProfileChangeRequest() else {
          print("failed to update name")
          return
      }
      
      changeRequest.displayName = displayName
      changeRequest.commitChanges { error in
          if let error = error {
              print("there was an error updating name")
              print(error.localizedDescription)
          }
          if let completion = completion {
              completion(Auth.auth().currentUser, error)
          }
      }
  }
  
  func firebaseAuth(credentials: AuthCredential) {
      Auth.auth().signIn(with: credentials) { (authResult, error) in
          if let error = error {
              let authError = error as NSError
              print(authError)
          }
          
          if let user = authResult?.user {
              
              print(user.displayName as Any)
              self.signInState = .signedIn
          }
        
        self.setLoggingIn(false)
      }
  }
  enum SignInState {
      case signedIn
      case signedOut
  }
}

public extension FirebaseAuthHelper {
  func facebookAuth(onFail:(() -> ())? = nil) {
    let loginManager = LoginManager()
    loginManager.logOut()
      if let presentingVC = UIApplication.shared.windows.first?.rootViewController{
          loginManager.logIn(permissions: ["public_profile", "email"], from: presentingVC) {(result, error) in
            print("Facebook Login Completion Handler")
            
            print(result?.description ?? "res nil")
            print(error?.localizedDescription ?? "err nil")
              guard error == nil else {
                self.facebook_signOut()
                self.isLoggingIn = false
                onFail?()
                  return
              }
              
              if let result =  result {
                  let credential = FacebookAuthProvider.credential(withAccessToken: result.token?.tokenString ?? "")
                  self.firebaseAuth(credentials: credential)
              }
          }
      }
  }
  
  func facebook_signOut() {
      let loginManager = LoginManager()
      
      loginManager.logOut()
      
      firebaseSignOut { _ in }
  }
}

public extension FirebaseAuthHelper {
  func googleAuth() {
      if GIDSignIn.sharedInstance.currentUser == nil,
         let clientID = FirebaseApp.app()?.options.clientID,
         let presentingVC = UIApplication.shared.windows.first?.rootViewController{
          
          GIDSignIn.sharedInstance.signIn(with: GIDConfiguration(clientID: clientID), presenting: presentingVC, hint: "Login Hint") { user, error in
              if error == nil {
                  if let user = user {
                      
                      if let idToken = user.authentication.idToken{
                          
                          let credential = GoogleAuthProvider.credential(withIDToken: idToken, accessToken: user.authentication.accessToken)
                          
                          self.firebaseAuth(credentials: credential)
                      } else {
                        self.setLoggingIn(false)
                      }
                      print("authenticated with google")
                  } else {
                      print("failed to unwrap optional user in GID signup")
                    self.setLoggingIn(false)
                  }
              } else {
                  print(error.debugDescription)
                self.setLoggingIn(false)
              }
          }
      }
  }
  func google_signOut() {
      GIDSignIn.sharedInstance.signOut()
      
      firebaseSignOut { _ in }
  }
}
#endif
