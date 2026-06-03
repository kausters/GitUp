//  Copyright (C) 2015-2019 Pierre-Olivier Latour <info@pol-online.net>
//
//  This program is free software: you can redistribute it and/or modify
//  it under the terms of the GNU General Public License as published by
//  the Free Software Foundation, either version 3 of the License, or
//  (at your option) any later version.
//
//  This program is distributed in the hope that it will be useful,
//  but WITHOUT ANY WARRANTY; without even the implied warranty of
//  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
//  GNU General Public License for more details.
//
//  You should have received a copy of the GNU General Public License
//  along with this program.  If not, see <http://www.gnu.org/licenses/>.

#if !__has_feature(objc_arc)
#error This file requires ARC
#endif

#import "GCTestCase.h"
#import "GCRepository+Index.h"

static NSString* _CommitSignature(GCCommit* commit) {
  git_buf buffer = {0};
  int status = git_commit_header_field(&buffer, commit.private, "gpgsig");
  if (status != GIT_OK) {
    git_buf_free(&buffer);
    return nil;
  }
  NSString* signature = [[NSString alloc] initWithBytes:buffer.ptr length:buffer.size encoding:NSUTF8StringEncoding];
  git_buf_free(&buffer);
  return signature;
}

static BOOL _ConfigureSSHSigningWithKeyPath(GCRepository* repository, NSString* keyPath) {
  return [repository writeConfigOptionForLevel:kGCConfigLevel_Local variable:@"commit.gpgsign" withValue:@"true" error:NULL] &&
         [repository writeConfigOptionForLevel:kGCConfigLevel_Local variable:@"gpg.format" withValue:@"ssh" error:NULL] &&
         [repository writeConfigOptionForLevel:kGCConfigLevel_Local variable:@"user.signingkey" withValue:keyPath error:NULL];
}

static NSString* _CreateFakeSSHSigner(NSString* directory, int exitStatus) {
  NSString* path = [directory stringByAppendingPathComponent:[[NSProcessInfo processInfo] globallyUniqueString]];
  NSString* contents = exitStatus == 0 ? @"#!/bin/sh\ncat >/dev/null\nprintf '%s\\n' '-----BEGIN SSH SIGNATURE-----' 'fake-signature' '-----END SSH SIGNATURE-----'\n"
                                      : [NSString stringWithFormat:@"#!/bin/sh\ncat >/dev/null\necho signer failed >&2\nexit %i\n", exitStatus];
  return ([contents writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:NULL] &&
          [[NSFileManager defaultManager] setAttributes:@{NSFilePosixPermissions : @(0755)} ofItemAtPath:path error:NULL])
             ? path
             : nil;
}

static GCCommit* _CreateCommitFromRepositoryIndex(GCRepository* repository, NSString* message, NSError** error) {
  GCCommit* commit = nil;
  git_index* index = NULL;
  git_tree* tree = NULL;

  index = [repository reloadRepositoryIndex:error];
  if (!index) {
    goto cleanup;
  }

  git_oid oid;
  CALL_LIBGIT2_FUNCTION_GOTO(cleanup, git_index_write_tree_to, &oid, index, repository.private);
  CALL_LIBGIT2_FUNCTION_GOTO(cleanup, git_tree_lookup, &tree, repository.private, &oid);
  commit = GCCreateCommitFromTreeWithOptionalSignature(repository, tree, NULL, 0, NULL, message, error);

cleanup:
  git_tree_free(tree);
  git_index_free(index);
  return commit;
}

@implementation GCEmptyRepositoryTests (GCCommitSigning)

- (void)testCommitSigningLeavesCommitsUnsignedWhenDisabledOrUnsupported {
  [self updateFileAtPath:@"unsigned.txt" withString:@"unsigned\n"];
  XCTAssertTrue([self.repository addFileToIndex:@"unsigned.txt" error:NULL]);
  GCCommit* unsignedCommit = _CreateCommitFromRepositoryIndex(self.repository, @"Unsigned", NULL);
  XCTAssertNotNil(unsignedCommit);
  XCTAssertNil(_CommitSignature(unsignedCommit));

  XCTAssertTrue([self.repository writeConfigOptionForLevel:kGCConfigLevel_Local variable:@"commit.gpgsign" withValue:@"true" error:NULL]);
  XCTAssertTrue([self.repository writeConfigOptionForLevel:kGCConfigLevel_Local variable:@"gpg.format" withValue:@"openpgp" error:NULL]);
  [self updateFileAtPath:@"openpgp.txt" withString:@"openpgp\n"];
  XCTAssertTrue([self.repository addFileToIndex:@"openpgp.txt" error:NULL]);
  GCCommit* openPGPCommit = _CreateCommitFromRepositoryIndex(self.repository, @"OpenPGP config remains unsigned", NULL);
  XCTAssertNotNil(openPGPCommit);
  XCTAssertNil(_CommitSignature(openPGPCommit));
}

- (void)testCommitSigningRequiresSSHKey {
  XCTAssertTrue([self.repository writeConfigOptionForLevel:kGCConfigLevel_Local variable:@"commit.gpgsign" withValue:@"true" error:NULL]);
  XCTAssertTrue([self.repository writeConfigOptionForLevel:kGCConfigLevel_Local variable:@"gpg.format" withValue:@"ssh" error:NULL]);
  [self updateFileAtPath:@"missing-key.txt" withString:@"missing key\n"];
  XCTAssertTrue([self.repository addFileToIndex:@"missing-key.txt" error:NULL]);
  NSError* error;
  XCTAssertNil(_CreateCommitFromRepositoryIndex(self.repository, @"Missing key", &error));
  XCTAssertTrue([error.localizedDescription containsString:@"user.signingkey"]);
}

- (void)testCommitSigningSupportsInlineKeyAndDefaultKeyCommand {
  NSString* signer = _CreateFakeSSHSigner(self.temporaryPath, 0);
  XCTAssertNotNil(signer);
  XCTAssertTrue([self.repository writeConfigOptionForLevel:kGCConfigLevel_Local variable:@"commit.gpgsign" withValue:@"true" error:NULL]);
  XCTAssertTrue([self.repository writeConfigOptionForLevel:kGCConfigLevel_Local variable:@"gpg.format" withValue:@"ssh" error:NULL]);
  XCTAssertTrue([self.repository writeConfigOptionForLevel:kGCConfigLevel_Local variable:@"gpg.ssh.program" withValue:signer error:NULL]);

  XCTAssertTrue([self.repository writeConfigOptionForLevel:kGCConfigLevel_Local variable:@"user.signingkey" withValue:@"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFakeInlineKey test@example.com" error:NULL]);
  [self updateFileAtPath:@"inline-key.txt" withString:@"inline key\n"];
  XCTAssertTrue([self.repository addFileToIndex:@"inline-key.txt" error:NULL]);
  GCCommit* inlineCommit = _CreateCommitFromRepositoryIndex(self.repository, @"Inline key", NULL);
  XCTAssertNotNil(inlineCommit);
  XCTAssertTrue([_CommitSignature(inlineCommit) containsString:@"BEGIN SSH SIGNATURE"]);

  XCTAssertTrue([self.repository writeConfigOptionForLevel:kGCConfigLevel_Local variable:@"user.signingkey" withValue:nil error:NULL]);
  XCTAssertTrue([self.repository writeConfigOptionForLevel:kGCConfigLevel_Local variable:@"gpg.ssh.defaultKeyCommand" withValue:@"printf 'key::ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIDefaultCommandKey test@example.com\\n'" error:NULL]);
  [self updateFileAtPath:@"default-key-command.txt" withString:@"default key command\n"];
  XCTAssertTrue([self.repository addFileToIndex:@"default-key-command.txt" error:NULL]);
  GCCommit* defaultCommandCommit = _CreateCommitFromRepositoryIndex(self.repository, @"Default key command", NULL);
  XCTAssertNotNil(defaultCommandCommit);
  XCTAssertTrue([_CommitSignature(defaultCommandCommit) containsString:@"BEGIN SSH SIGNATURE"]);
}

- (void)testCommitSigningSupportsKeyPath {
  NSString* keyPath = [self.temporaryPath stringByAppendingPathComponent:@"signing_key"];
  GCTask* keygen = [[GCTask alloc] initWithExecutablePath:@"/usr/bin/ssh-keygen"];
  int status;
  NSArray* keygenArguments = @[ @"-t", @"ed25519", @"-f", keyPath, @"-N", @"", @"-q" ];
  BOOL keygenSuccess = [keygen runWithArguments:keygenArguments stdin:nil stdout:NULL stderr:NULL exitStatus:&status error:NULL];
  XCTAssertTrue(keygenSuccess);
  XCTAssertEqual(status, 0);
  XCTAssertTrue(_ConfigureSSHSigningWithKeyPath(self.repository, keyPath));

  [self updateFileAtPath:@"path-key.txt" withString:@"path key\n"];
  XCTAssertTrue([self.repository addFileToIndex:@"path-key.txt" error:NULL]);
  GCCommit* commit = _CreateCommitFromRepositoryIndex(self.repository, @"Path key", NULL);
  XCTAssertNotNil(commit);
  XCTAssertTrue([_CommitSignature(commit) containsString:@"BEGIN SSH SIGNATURE"]);

  NSString* publicKey = [NSString stringWithContentsOfFile:[keyPath stringByAppendingString:@".pub"] encoding:NSUTF8StringEncoding error:NULL];
  NSString* allowedSignersPath = [self.temporaryPath stringByAppendingPathComponent:@"allowed_signers"];
  NSString* allowedSigners = [NSString stringWithFormat:@"bot@example.com %@", publicKey];
  XCTAssertTrue([allowedSigners writeToFile:allowedSignersPath atomically:YES encoding:NSUTF8StringEncoding error:NULL]);
  NSString* allowedSignersConfig = [NSString stringWithFormat:@"gpg.ssh.allowedSignersFile=%@", allowedSignersPath];
  NSString* verifyOutput = [self runGitCLTWithRepository:self.repository command:@"-c", allowedSignersConfig, @"verify-commit", commit.SHA1, nil];
  XCTAssertNotNil(verifyOutput);
}

- (void)testCommitSigningFailsOnSignerFailure {
  NSString* signer = _CreateFakeSSHSigner(self.temporaryPath, 7);
  XCTAssertNotNil(signer);
  XCTAssertTrue([self.repository writeConfigOptionForLevel:kGCConfigLevel_Local variable:@"commit.gpgsign" withValue:@"true" error:NULL]);
  XCTAssertTrue([self.repository writeConfigOptionForLevel:kGCConfigLevel_Local variable:@"gpg.format" withValue:@"ssh" error:NULL]);
  XCTAssertTrue([self.repository writeConfigOptionForLevel:kGCConfigLevel_Local variable:@"gpg.ssh.program" withValue:signer error:NULL]);
  XCTAssertTrue([self.repository writeConfigOptionForLevel:kGCConfigLevel_Local variable:@"user.signingkey" withValue:@"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFailingSignerKey test@example.com" error:NULL]);
  [self updateFileAtPath:@"failing-signer.txt" withString:@"failing signer\n"];
  XCTAssertTrue([self.repository addFileToIndex:@"failing-signer.txt" error:NULL]);
  NSError* error;
  XCTAssertNil(_CreateCommitFromRepositoryIndex(self.repository, @"Failing signer", &error));
  XCTAssertTrue([error.localizedDescription containsString:@"non-zero status"]);
}

@end
