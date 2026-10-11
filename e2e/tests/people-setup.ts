// Global setup of the people phase: filled in below.
import { waitForApi } from "./lib";

export default async function globalSetup(): Promise<void> {
  await waitForApi();
}
