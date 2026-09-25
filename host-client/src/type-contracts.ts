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
