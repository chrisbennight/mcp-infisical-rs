import { HostClient } from './client.js';

/** Keep complete pages in the host and return only a bounded project summary. */
export async function summarizeProjects(client: HostClient, maximumPages = 10): Promise<{
  projects: Array<{ id: string; name: string }>;
  complete: boolean;
}> {
  if (!Number.isSafeInteger(maximumPages) || maximumPages < 1 || maximumPages > 100) {
    throw new Error('maximumPages must be an integer between 1 and 100');
  }
  const selected = new Map<string, { id: string; name: string }>();
  let offset = 0;
  for (let page = 0; page < maximumPages; page++) {
    const outcome = await client.invoke('projects.list', { limit: 100, offset, includeDetails: false });
    if (outcome.kind === 'error') throw new Error('Project inventory failed; inspect the wrapped error in the host');
    const result = outcome.value.read();
    for (const project of result.items) selected.set(project.id, { id: project.id, name: project.name });
    if (!result.next) return { projects: [...selected.values()], complete: true };
    if (result.next.offset <= offset) throw new Error('Project continuation did not advance');
    offset = result.next.offset;
  }
  return { projects: [...selected.values()], complete: false };
}

/** Join a bounded set of selected projects to their first environment page. */
export async function summarizeProjectEnvironments(client: HostClient, namePrefix: string): Promise<{
  projects: Array<{ id: string; name: string; environments: string[]; complete: boolean }>;
  complete: boolean;
}> {
  const inventory = await summarizeProjects(client, 3);
  const matches = inventory.projects.filter(project => project.name.startsWith(namePrefix));
  const projects = [];
  for (const project of matches.slice(0, 10)) {
    const outcome = await client.invoke('environments.list', { projectId: project.id, limit: 100 });
    if (outcome.kind === 'error') throw new Error('Environment inventory failed; inspect the wrapped error in the host');
    const result = outcome.value.read();
    if (result.projectId !== project.id) throw new Error('Environment result does not match the requested project');
    projects.push({ ...project, environments: result.environments?.items.map(item => item.slug) ?? [],
      complete: result.environments != null && !result.environments.next });
  }
  return { projects, complete: inventory.complete && matches.length <= 10 && projects.every(project => project.complete) };
}
