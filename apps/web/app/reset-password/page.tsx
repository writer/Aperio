import { Suspense } from "react";
import { ResetPasswordPage } from "../../components/auth/reset-password-page";

export default function ResetPassword() {
  return (
    <Suspense fallback={null}>
      <ResetPasswordPage />
    </Suspense>
  );
}
