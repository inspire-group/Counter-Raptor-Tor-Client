#ifndef QUEUE_H
#define QUEUE_H

// A linked list (LL) node to store a queue entry
typedef struct QNode
{
  int key;
  struct QNode *next;
} QNode;

// The queue, front stores the front node of LL and rear stores ths
// last node of LL
typedef struct Queue
{
  struct QNode *front, *rear;
} Queue;

/* create an empty queue */
Queue *createQueue();

/* insert an element at the end of the queue */
void enQueue(Queue *q, int k);

/* delete the front element on the queue and return it */
QNode *deQueue(Queue *q);

/* return a true value if and only if the queue is empty */
int queue_empty(Queue *q);

#endif
