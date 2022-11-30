/** When your routing table is too long, you can split it into small modules **/

import Layout from '@/layout'

const systemRouter = {
  path: '/system',
  component: Layout,
  redirect: '/system/user',
  name: 'sys',
  meta: {
    title: '系统管理',
    icon: 'star'
  },
  children: [
    // {
    //   path: 'dynamic-table',
    //   component: () => import('@/views/table/dynamic-table/index'),
    //   name: 'DynamicTable',
    //   meta: { title: 'Dynamic Table' }
    // },
    // {
    //   path: 'drag-table',
    //   component: () => import('@/views/table/drag-table'),
    //   name: 'DragTable',
    //   meta: { title: 'Drag Table' }
    // },
    {
      path: 'user',
      component: () => import('@/views/table/inline-edit-table'),
      name: 'InlineTable',
      meta: { title: '用户管理', icon: 'user' }
    },
    {
      path: 'role',
      component: () => import('@/views/table/complex-table'),
      name: 'ComplexTable',
      meta: { title: '角色管理', icon: 'role' }
    },
    {
      path: 'menu',
      component: () => import('@/views/table/complex-table'),
      name: 'ComplexTable',
      meta: { title: '菜单管理', icon: 'menu' }
    }
  ]
}
export default systemRouter
