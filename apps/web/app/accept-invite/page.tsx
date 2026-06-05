import { Suspense } from "react";
import { AcceptInvitePage } from "../../components/auth/accept-invite-page";

export default function AcceptInvite() {
  return (
    <Suspense fallback={null}>
      <AcceptInvitePage />
    </Suspense>
  );
}
