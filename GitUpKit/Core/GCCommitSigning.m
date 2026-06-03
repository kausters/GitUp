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

#import "GCPrivate.h"

#if !TARGET_OS_IPHONE

static NSString* _StringFromTaskOutput(NSData* data) {
  return [[[NSString alloc] initWithData:data encoding:NSUTF8StringEncoding] stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
}

static BOOL _ReadConfigBool(GCRepository* repository, const char* variable, BOOL* value, NSError** error) {
  BOOL success = NO;
  git_config* config = NULL;
  int boolValue = 0;
  int status;

  CALL_LIBGIT2_FUNCTION_GOTO(cleanup, git_repository_config, &config, repository.private);
  status = git_config_get_bool(&boolValue, config, variable);
  if (status == GIT_ENOTFOUND) {
    *value = NO;
    success = YES;
    goto cleanup;
  }
  CHECK_LIBGIT2_FUNCTION_CALL(goto cleanup, status, == GIT_OK);
  *value = boolValue ? YES : NO;
  success = YES;

cleanup:
  git_config_free(config);
  return success;
}

static BOOL _ShouldSSHSignCommit(GCRepository* repository, BOOL* shouldSign, NSError** error) {
  BOOL gpgSign = NO;
  if (!_ReadConfigBool(repository, "commit.gpgsign", &gpgSign, error)) {
    return NO;
  }
  if (!gpgSign) {
    *shouldSign = NO;
    return YES;
  }

  NSString* format = [[repository readConfigOptionForVariable:@"gpg.format" error:NULL] value];
  if (!format.length || ([format caseInsensitiveCompare:@"ssh"] != NSOrderedSame)) {
    // v1 intentionally supports SSH commit signing only. Preserve existing GitUp behavior for OpenPGP/X.509 configs by creating an unsigned commit.
    *shouldSign = NO;
    return YES;
  }

  *shouldSign = YES;
  return YES;
}

static NSString* _CommitSigningPATH(GCRepository* repository, NSError** error) {
  static NSString* cachedPATH = nil;
  if (cachedPATH == nil) {
    cachedPATH = [repository getPATHUsingShell:NSProcessInfo.processInfo.environment[@"SHELL"] error:error] ?: [repository getPATHUsingShell:@"/bin/sh" error:error];
    XLOG_DEBUG_CHECK(cachedPATH);
  }
  return cachedPATH;
}

static BOOL _LooksLikeInlineSSHKey(NSString* key) {
  return [key hasPrefix:@"ssh-"] || [key hasPrefix:@"ecdsa-"] || [key hasPrefix:@"sk-"];
}

static NSString* _SSHKeyFromDefaultKeyCommand(GCRepository* repository, NSString* command, NSError** error) {
  NSString* path = _CommitSigningPATH(repository, error);
  if (!path) {
    return nil;
  }

  GCTask* task = [[GCTask alloc] initWithExecutablePath:@"/bin/sh"];
  task.currentDirectoryPath = repository.workingDirectoryPath ?: repository.repositoryPath;
  task.additionalEnvironment = @{@"PATH" : path};
  int status;
  NSData* stdoutData;
  NSData* stderrData;
  if (![task runWithArguments:@[ @"-c", command ] stdin:nil stdout:&stdoutData stderr:&stderrData exitStatus:&status error:error]) {
    return nil;
  }
  if (status != 0) {
    if (error) {
      NSString* output = _StringFromTaskOutput(stderrData.length ? stderrData : stdoutData);
      *error = GCNewError(kGCErrorCode_Generic, [NSString stringWithFormat:@"SSH signing default key command exited with non-zero status (%i)%@", status, output.length ? [NSString stringWithFormat:@": %@", output] : @""]);
    }
    return nil;
  }

  NSString* output = [[NSString alloc] initWithData:stdoutData encoding:NSUTF8StringEncoding];
  for (NSString* line in [output componentsSeparatedByCharactersInSet:[NSCharacterSet newlineCharacterSet]]) {
    NSString* trimmedLine = [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    if ([trimmedLine hasPrefix:@"key::"]) {
      NSString* key = [trimmedLine substringFromIndex:5];
      return key.length ? key : nil;
    }
  }
  if (error) {
    *error = GCNewError(kGCErrorCode_Generic, @"SSH signing default key command did not return a key:: entry");
  }
  return nil;
}

static NSString* _TemporaryKeyFileForInlineSSHKey(NSString* key, NSError** error) {
  NSString* path = [NSTemporaryDirectory() stringByAppendingPathComponent:[[NSProcessInfo processInfo] globallyUniqueString]];
  NSString* contents = [key hasSuffix:@"\n"] ? key : [key stringByAppendingString:@"\n"];
  if (![contents writeToFile:path atomically:YES encoding:NSUTF8StringEncoding error:error]) {
    return nil;
  }
  return path;
}

static NSString* _SSHSigningKeyPath(GCRepository* repository, NSString** temporaryPath, NSError** error) {
  NSString* key = [[repository readConfigOptionForVariable:@"user.signingkey" error:NULL] value];
  if (key.length) {
    key = [key stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
  } else {
    NSString* command = [[repository readConfigOptionForVariable:@"gpg.ssh.defaultKeyCommand" error:NULL] value];
    if (!command.length) {
      if (error) {
        *error = GCNewError(kGCErrorCode_Generic, @"SSH commit signing requires user.signingkey or gpg.ssh.defaultKeyCommand");
      }
      return nil;
    }
    key = _SSHKeyFromDefaultKeyCommand(repository, command, error);
    if (!key) {
      return nil;
    }
  }

  if ([key hasPrefix:@"key::"]) {
    key = [key substringFromIndex:5];
  }
  if (_LooksLikeInlineSSHKey(key)) {
    NSString* path = _TemporaryKeyFileForInlineSSHKey(key, error);
    if (!path) {
      return nil;
    }
    *temporaryPath = path;
    return path;
  }

  NSString* path = key.stringByExpandingTildeInPath;
  if (!path.absolutePath) {
    NSString* workingDirectoryPath = repository.workingDirectoryPath ?: repository.repositoryPath;
    NSString* relativePath = [workingDirectoryPath stringByAppendingPathComponent:path];
    if ([[NSFileManager defaultManager] fileExistsAtPath:relativePath]) {
      path = relativePath;
    }
  }
  return path;
}

static NSString* _SSHSignatureForCommitBuffer(GCRepository* repository, NSData* commitBuffer, NSError** error) {
  NSString* temporaryKeyPath = nil;
  NSString* keyPath = _SSHSigningKeyPath(repository, &temporaryKeyPath, error);
  if (!keyPath) {
    return nil;
  }

  NSString* path = _CommitSigningPATH(repository, error);
  if (!path) {
    if (temporaryKeyPath) {
      [[NSFileManager defaultManager] removeItemAtPath:temporaryKeyPath error:NULL];
    }
    return nil;
  }

  NSString* program = [[repository readConfigOptionForVariable:@"gpg.ssh.program" error:NULL] value];
  program = program.length ? program.stringByExpandingTildeInPath : @"ssh-keygen";

  GCTask* task = [[GCTask alloc] initWithExecutablePath:@"/usr/bin/env"];
  task.currentDirectoryPath = repository.workingDirectoryPath ?: repository.repositoryPath;
  task.additionalEnvironment = @{@"PATH" : path};
  int status;
  NSData* stdoutData;
  NSData* stderrData;
  NSArray* arguments = @[ program, @"-Y", @"sign", @"-n", @"git", @"-f", keyPath ];
  BOOL success = [task runWithArguments:arguments stdin:commitBuffer stdout:&stdoutData stderr:&stderrData exitStatus:&status error:error];
  if (temporaryKeyPath) {
    [[NSFileManager defaultManager] removeItemAtPath:temporaryKeyPath error:NULL];
  }
  if (!success) {
    return nil;
  }
  if (status != 0) {
    if (error) {
      NSString* output = _StringFromTaskOutput(stderrData.length ? stderrData : stdoutData);
      *error = GCNewError(kGCErrorCode_Generic, [NSString stringWithFormat:@"SSH commit signer exited with non-zero status (%i)%@", status, output.length ? [NSString stringWithFormat:@": %@", output] : @""]);
    }
    return nil;
  }

  NSString* signature = _StringFromTaskOutput(stdoutData);
  if (!signature.length) {
    if (error) {
      *error = GCNewError(kGCErrorCode_Generic, @"SSH commit signer did not return a signature");
    }
    return nil;
  }
  return signature;
}

#endif

GCCommit* GCCreateCommitFromTreeWithOptionalSignature(GCRepository* repository, git_tree* tree, const git_commit** parents, NSUInteger count, const git_signature* author, NSString* message, NSError** error) {
  GCCommit* commit = nil;
  git_signature* signature = NULL;
  git_commit* newCommit = NULL;
  NSData* cleanedMessage = nil;
#if !TARGET_OS_IPHONE
  git_buf commitBuffer = {0};
  NSData* commitData = nil;
  NSString* sshSignature = nil;
  BOOL shouldSign = NO;
#endif

  git_oid oid;
  CALL_LIBGIT2_FUNCTION_GOTO(cleanup, git_signature_default, &signature, repository.private);
  cleanedMessage = GCCleanedUpCommitMessage(message);
#if !TARGET_OS_IPHONE
  if (!_ShouldSSHSignCommit(repository, &shouldSign, error)) {
    goto cleanup;
  }

  if (shouldSign) {
    CALL_LIBGIT2_FUNCTION_GOTO(cleanup, git_commit_create_buffer, &commitBuffer, repository.private, author ? author : signature, signature, NULL, cleanedMessage.bytes, tree, count, parents);
    commitData = [[NSData alloc] initWithBytes:commitBuffer.ptr length:commitBuffer.size];
    sshSignature = _SSHSignatureForCommitBuffer(repository, commitData, error);
    if (!sshSignature) {
      goto cleanup;
    }
    CALL_LIBGIT2_FUNCTION_GOTO(cleanup, git_commit_create_with_signature, &oid, repository.private, commitBuffer.ptr, sshSignature.UTF8String, "gpgsig");
  } else {
#endif
    CALL_LIBGIT2_FUNCTION_GOTO(cleanup, git_commit_create, &oid, repository.private, NULL, author ? author : signature, signature, NULL, cleanedMessage.bytes, tree, count, parents);
#if !TARGET_OS_IPHONE
  }
#endif
  CALL_LIBGIT2_FUNCTION_GOTO(cleanup, git_commit_lookup, &newCommit, repository.private, &oid);
  commit = [[GCCommit alloc] initWithRepository:repository commit:newCommit];
  newCommit = NULL;

cleanup:
  git_commit_free(newCommit);
#if !TARGET_OS_IPHONE
  git_buf_free(&commitBuffer);
#endif
  git_signature_free(signature);
  return commit;
}
