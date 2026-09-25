import type { HostClient, InputByOperation, OutputByOperation } from './client.js';
// Compile-only fixtures; no transport runs from this module.
function contracts(client: HostClient): void {
  void client.invoke('projects.list', { limit: 10 });
  // @ts-expect-error operation names are closed
  void client.invoke('projects.missing', {});
  // @ts-expect-error numeric pagination cannot be a string
  void client.invoke('projects.list', { limit: '10' });
  // @ts-expect-error closed input rejects unknown fields
  void client.invoke('projects.list', { arbitrary: true });
  // @ts-expect-error required project scope cannot be omitted
  const environment: InputByOperation['environments.list'] = {};
  void environment;
  const names = (result: OutputByOperation['projects.list']): string[] => result.items.map(item => item.name);
  void names;
}
void contracts;

async function fileContracts(client: HostClient): Promise<void> {
  const outcome = await client.invokeFile('identityTokenAuth.tokens.create', { identityId: 'identity-1' });
  if (outcome.kind === 'success') {
    const result = outcome.value.read();
    const operation: 'identityTokenAuth.tokens.create' = result.operation;
    const uri: string = result.resultFile.uri;
    const identifiers: string[] = result.reconciliation.map(receipt => receipt.id);
    for (const receipt of result.reconciliation) {
      const kind: 'clientSecret' | 'token' | 'dynamicLease' | 'certificate' | 'certificateRequest' | 'sshCertificate' = receipt.kind;
      void kind;
    }
    // @ts-expect-error the successful operation retains its exact literal
    const otherOperation: 'projects.list' = result.operation;
    // @ts-expect-error file URIs remain strings
    const numericUri: number = result.resultFile.uri;
    void [operation, uri, identifiers, otherOperation, numericUri];
  }
}
void fileContracts;
