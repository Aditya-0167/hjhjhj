# cdap: unauthenticated context-setting endpoints on the GCP metadata-proxy
# sidecar, co-located with untrusted task-worker code

**Component:** `cdap-app-fabric` (`GcpMetadataHttpHandlerInternal`, the
`ArtifactLocalizer` sidecar), `cdap-security` (`InternalAccessEnforcer`),
`cdap-common` (`TaskWorkerHttpHandlerInternal`)
**Repo:** cdapio/cdap (Cloud VRP scope)
**Commit tested against:** `35493c2a4f66e16f4324ee4ef4c7243c64cd8a72` (develop branch)

## Summary

CDAP's `NAMESPACED_SERVICE_ACCOUNTS` feature (on by default since CDAP
6.10.0 — features default to enabled after introduction unless explicitly
marked otherwise, and this one isn't) gives each namespace its own distinct
GCP workload-identity credential, vended to task-worker pods via a local
sidecar (`GcpMetadataHttpHandlerInternal`) that impersonates the real GCP
metadata server. Task-worker code that would normally call the real metadata
endpoint (standard behavior for any GCP client library) transparently talks
to this sidecar instead, which returns a namespace-scoped token.

Two endpoints on that sidecar have **no authentication whatsoever**:

```java
// packages GcpMetadataHttpHandlerInternal.java
@PUT
@Path("/set-context")
public void setContext(FullHttpRequest request, HttpResponder responder)
    throws BadRequestException {
  this.gcpMetadataTaskContext = getGcpMetadataTaskContext(request);
  ...
}

@DELETE
@Path("/clear-context")
public void clearContext(HttpRequest request, HttpResponder responder) {
  this.gcpMetadataTaskContext = null;
  ...
}
```

`gcpMetadataTaskContext` is a single shared instance field (`@Singleton`) —
whatever namespace is set here determines which namespace's credential the
subsequent `GET /computeMetadata/v1/instance/service-accounts/default/token`
call returns. And per CDAP's own code documentation, this sidecar is not a
separate, isolated service — it runs in the same pod as the task-worker
process that executes customer-supplied code:

```java
// TaskWorkerTwillApplication.java
/**
 * The {@link TwillApplication} for launching task workers along with
 * artifact localizers as sidecar containers.
 */
```

Containers in the same Kubernetes pod share the loopback network interface.
The sidecar binds to loopback only (`InetAddress.getLoopbackAddress()`),
which correctly blocks cross-pod/external access — but does nothing against
the task-worker's own code sharing that same loopback.

## What I confirmed, and what I could not break

I want to be direct that I chased this as far as I could and it does **not**
end in a demonstrated credential-theft exploit. Two independent, correctly-
implemented controls stopped it:

1. **Cryptographic verification on the internal credential path.** The
   sidecar's outgoing call to app-fabric's provisioning endpoint
   (`GcpWorkloadIdentityHttpHandlerInternal.provisionCredential`) carries
   whatever `userId`/`userCredential` were in the (unauthenticated)
   `/set-context` payload. If those are omitted — the simplest attack —
   the request arrives with a default `EMPTY_USER_CREDENTIAL` of type
   `INTERNAL`, which routes to `InternalAccessEnforcer.enforce()`:

   ```java
   // InternalAccessEnforcer.java
   accessToken = accessTokenCodec.decode(Base64.getDecoder().decode(credential.getValue()));
   ...
   tokenManager.validateSecret(accessToken);
   ```

   This Base64-decodes the credential as a signed `AccessToken` and verifies
   it against the server's secret. A placeholder/forged string fails to
   decode and the request is rejected. **I traced this precisely and I'm
   confident the naive "just omit the credential" bypass does not work.**

2. **Mandatory worker termination after untrusted code.** I considered
   whether a task-worker pod could be *reused* across sequential tasks for
   *different* namespaces — malicious code from task A leaving a background
   thread polling the token endpoint, timed to catch task B's legitimate
   context before B's own code consumes it. CDAP already defends against
   this deliberately: `RunnableTaskContext`'s `terminateOnComplete` defaults
   to `true`, and every call site that runs actual customer/plugin code sets
   it explicitly based on trust level, e.g.:

   ```java
   // RemoteValidationTask.java
   context.setTerminateOnComplete(!ArtifactScope.SYSTEM.equals(spec.getPlugin().getArtifact().getScope()));
   ```

   i.e. any non-system-scope (customer-supplied) code execution destroys the
   worker pod immediately after. `TaskWorkerHttpHandlerInternal` also forces
   termination on any unhandled exception ("Potentially ran user code, hence
   terminate the runner"). This closes the reuse window my race-condition
   idea depended on.

I don't have visibility into Google's actual production authorizer plugin
(the `EXTERNAL` credential-type path routes to a pluggable
`AccessController` extension, which for real Cloud Data Fusion is almost
certainly a proprietary Cloud-IAM-integrated implementation, not anything in
this open-source repo) — so I can't rule out that a forged `EXTERNAL`-typed
credential behaves differently there. But I have no evidence either way, and
I'm not going to imply a finding I can't back up.

## Why this is still worth reporting

Despite not yielding a working exploit, the underlying fact stands on its
own: **`/set-context` and `/clear-context` — endpoints that control which
namespace's identity a credential-vending mechanism will vend — accept
requests from anything that can reach loopback, with no token, no signature,
no check of any kind.** That's a real gap in a security-sensitive component,
independently of whether today's downstream controls happen to catch the
obvious way to abuse it. Defense-in-depth exists precisely so that a second
bug elsewhere (in either of the two controls above, or in some path I
haven't found) doesn't immediately become a full cross-tenant credential
theft chain. Right now, this endpoint is one gap away from being that chain,
where it should be zero.

## Reproduction / verification

**Disclosure up front, same as the SSRF report:** no `javac`/Maven or Maven
Central access in this sandbox, so this is verified by direct, complete
reading of the real source (all files saved and included, see
`source-excerpts/`) and call-chain tracing across ten files spanning four
Gradle modules, not by compiling and running the actual Java. I'm not
claiming a live-executed PoC here — I want that limitation to be as visible
in this report as it was in my own investigation.

What I did concretely verify by reading, end to end, cited by file:

- `GcpMetadataHttpHandlerInternal.java`: `setContext`/`clearContext` have no
  auth check of any kind — confirmed by reading every line of both methods.
- `TaskWorkerTwillApplication.java`: the sidecar and task-worker are
  co-located "as sidecar containers" in the application's own Javadoc.
- `GcpWorkloadIdentityInternalAuthenticator.java`: outgoing internal auth
  headers are populated directly from the (attacker-reachable)
  `GcpMetadataTaskContext` object, no independent verification at this
  layer.
- `GcpWorkloadIdentityHttpHandlerInternal.java`: the app-fabric endpoint
  takes `namespace` from the URL path with no check binding it to the
  calling context.
- `DefaultNamespaceCredentialProviderService.java`: the actual enforcement
  call (`NamespacePermission.PROVISION_CREDENTIAL`) — confirmed present,
  which is what ultimately blocks the naive attack.
- `InternalAccessEnforcer.java`: confirmed the enforcement is real
  cryptographic verification, not a rubber stamp.
- `RemoteValidationTask.java` / `TaskWorkerHttpHandlerInternal.java`:
  confirmed the terminate-after-untrusted-code policy that closes the reuse
  window.

## Not yet done

- No live Cloud Data Fusion instance to test against — everything here is
  static analysis, not dynamic exploitation.
- Could not evaluate Google's actual production `AccessController` extension
  for the `EXTERNAL` credential-type path (proprietary, not in this repo).
- Did not check whether `SystemAppTask`/`ConfiguratorTask` (the other
  callers of `setTerminateOnComplete`) have any narrower condition under
  which non-system code could still avoid termination — spent the available
  time on the two clearest paths (`RemoteValidationTask`,
  `TaskWorkerHttpHandlerInternal`'s catch-all) rather than auditing every
  caller exhaustively.

## Suggested fix

- Require an unforgeable, per-task shared secret (e.g. a token minted by
  app-fabric at task-dispatch time, passed to the task-worker container via
  an env var or mounted file the sidecar container also has access to but
  the reused-across-tasks HTTP surface does not) on `/set-context` and
  `/clear-context`, so only the legitimate orchestration call — not
  arbitrary same-pod code — can set the context.
- At minimum, bind the sidecar's `/set-context` to a value it received once
  at pod startup (e.g. from the pod spec / a file only the orchestrator can
  write) rather than accepting it as mutable, replayable HTTP input for the
  pod's entire lifetime.
